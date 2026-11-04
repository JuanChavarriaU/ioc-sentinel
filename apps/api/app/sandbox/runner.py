"""
Host-side sandbox runner.

Spawns ONE ephemeral, hardened container per investigation, collects the single
JSON result line, and destroys the container no matter what happened.
Every lifecycle step is recorded as a telemetry event -> Containment Log.

CLI:  python -m app.sandbox.runner https://suspicious.example [--allow-private]
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import docker
from docker.errors import APIError, ImageNotFound, NotFound
from requests.exceptions import ConnectionError as ReqConnectionError
from requests.exceptions import ReadTimeout

from ..config import settings
from .url_guard import normalize_target

RESULT_MARKER = "@@IOC_RESULT@@"


@dataclass
class SandboxRun:
    scan_id: str
    url: str
    verdict: str = "pending"  # completed | timeout | oom_killed | crashed | error
    exit_code: int | None = None
    result: dict = field(default_factory=dict)
    host_events: list[dict] = field(default_factory=list)
    stderr_tail: str = ""

    def ev(self, kind: str, **data) -> None:
        self.host_events.append({"t": round(time.time(), 3), "src": "host", "kind": kind, **data})

    @property
    def containment_log(self) -> list[dict]:
        inner = [{**e, "src": "sandbox"} for e in self.result.get("events", [])]
        return sorted(self.host_events + inner, key=lambda e: e["t"])


def _hardening_kwargs() -> dict:
    """The blast-radius controls. Keep this function small and auditable."""
    kw = dict(
        network=settings.sandbox_network,      # jail bridge: public egress only (see infra/vm/jail-network.sh)
        dns=settings.sandbox_dns,              # public resolvers, never the host resolver
        read_only=True,                        # immutable root filesystem
        tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=256m,mode=1777"},  # scratch in RAM, wiped on destroy
        cap_drop=["ALL"],                      # no Linux capabilities at all
        security_opt=["no-new-privileges:true"],
        user=settings.sandbox_user,            # non-root inside the container
        mem_limit=settings.sandbox_mem,
        memswap_limit=settings.sandbox_mem,    # no swap escape hatch
        nano_cpus=int(settings.sandbox_cpus * 1e9),
        pids_limit=settings.sandbox_pids,      # fork-bomb guard
        shm_size="64m",
        ulimits=[docker.types.Ulimit(name="nofile", soft=1024, hard=1024)],
        ipc_mode="private",
        environment={                          # NOTE: zero secrets cross this line
            "NAV_TIMEOUT_MS": str(settings.nav_timeout_ms),
            "DWELL_MS": str(settings.dwell_ms),
        },
        labels={"app": "ioc-sentinel", "role": "sandbox"},
        log_config=docker.types.LogConfig(type="json-file", config={"max-size": "50m"}),
        detach=True,
    )
    if settings.sandbox_runtime:
        kw["runtime"] = settings.sandbox_runtime  # e.g. "runsc" (gVisor)
    return kw


def run_in_sandbox(url: str, *, allow_private: bool = False, client=None) -> SandboxRun:
    target = url if allow_private else normalize_target(url)
    run = SandboxRun(scan_id=uuid.uuid4().hex[:12], url=target)
    client = client or docker.from_env()
    kw = _hardening_kwargs()
    run.ev(
        "spawn",
        image=settings.sandbox_image,
        runtime=settings.sandbox_runtime or "runc",
        network=kw["network"],
        limits={"mem": settings.sandbox_mem, "cpus": settings.sandbox_cpus, "pids": settings.sandbox_pids,
                "timeout_s": settings.sandbox_timeout_s},
        secrets_passed=0,
    )

    container = None
    try:
        container = client.containers.run(settings.sandbox_image, command=[target], name=f"ioc-sbx-{run.scan_id}", **kw)
        run.ev("running", container=container.short_id)
        try:
            status = container.wait(timeout=settings.sandbox_timeout_s)
            run.exit_code = status.get("StatusCode")
        except (ReadTimeout, ReqConnectionError):
            run.verdict = "timeout"
            run.ev("timeout_kill", after_s=settings.sandbox_timeout_s)
            try:
                container.kill()
            except APIError:
                pass

        container.reload()
        state = container.attrs.get("State", {})
        if state.get("OOMKilled"):
            run.verdict = "oom_killed"
            run.ev("oom_kill", mem_limit=settings.sandbox_mem)

        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
        run.stderr_tail = container.logs(stdout=False, stderr=True).decode("utf-8", "replace")[-4000:]
        line = next((ln for ln in reversed(stdout.splitlines()) if ln.startswith(RESULT_MARKER)), None)
        if line:
            run.result = json.loads(line[len(RESULT_MARKER):])
            if run.verdict == "pending":
                run.verdict = "error" if "fatal" in run.result else "completed"
        elif run.verdict == "pending":
            run.verdict = "crashed"
            run.ev("no_result", exit_code=run.exit_code)
    except ImageNotFound:
        run.verdict = "error"
        run.ev("error", error=f"sandbox image not found: {settings.sandbox_image} (run `make sandbox-image`)")
    except (APIError, NotFound) as exc:
        run.verdict = "error"
        run.ev("error", error=str(exc)[:500])
    finally:
        if container is not None:
            t0 = time.time()
            try:
                container.remove(force=True)
                run.ev("destroyed", container=container.short_id, ms=round((time.time() - t0) * 1000))
            except (APIError, NotFound) as exc:
                run.ev("destroy_failed", error=str(exc)[:300])
    return run


def save_artifacts(run: SandboxRun, base_dir: Path | None = None) -> Path:
    """Persist evidence on the HOST (outside the sandbox) under data/scans/<id>/."""
    out = (base_dir or settings.data_dir) / "scans" / run.scan_id
    out.mkdir(parents=True, exist_ok=True)
    res = dict(run.result)
    shot = res.pop("screenshot_png_b64", None)
    har = res.pop("har_gz_b64", None)
    if shot:
        (out / "screenshot.png").write_bytes(base64.b64decode(shot))
    if har:
        (out / "session.har").write_bytes(gzip.decompress(base64.b64decode(har)))
    res.pop("events", None)
    summary = {
        "scan_id": run.scan_id,
        "url": run.url,
        "verdict": run.verdict,
        "exit_code": run.exit_code,
        "artifacts": {"screenshot": bool(shot), "har": bool(har)},
        "observations": res,
        "containment_log": run.containment_log,
        "stderr_tail": run.stderr_tail,
    }
    (out / "result.json").write_text(json.dumps(summary, indent=2, default=str))
    return out


def _cli() -> int:
    ap = argparse.ArgumentParser(description="Run one URL through the IoC Sentinel sandbox")
    ap.add_argument("url")
    ap.add_argument("--allow-private", action="store_true", help="skip host URL guard (local trap testing only)")
    args = ap.parse_args()
    run = run_in_sandbox(args.url, allow_private=args.allow_private)
    out = save_artifacts(run)
    obs = run.result
    print(f"\nscan {run.scan_id}  verdict={run.verdict}  exit={run.exit_code}  -> {out}")
    print(f"final_url={obs.get('final_url')} status={obs.get('status')} hosts={len(obs.get('hosts', []))}")
    print("\nContainment log:")
    for e in run.containment_log:
        extra = {k: v for k, v in e.items() if k not in ("t", "src", "kind")}
        print(f"  [{e['src']:7}] {e['kind']:<20} {json.dumps(extra, default=str)[:140]}")
    if run.verdict != "completed" and run.stderr_tail:
        print("\nstderr tail:\n" + run.stderr_tail[-1500:])
    return 0 if run.verdict == "completed" else 1


if __name__ == "__main__":
    sys.exit(_cli())
