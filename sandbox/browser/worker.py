"""
IoC Sentinel - sandboxed browser worker.

Runs INSIDE an ephemeral, credential-less container. It receives a single URL,
visits it with headless Chromium, and prints ONE JSON line to stdout prefixed
with RESULT_MARKER. Nothing else leaves the container.

Contract (host <-> sandbox):
  argv[1]            URL to investigate (http/https only)
  env NAV_TIMEOUT_MS navigation timeout (default 20000)
  env DWELL_MS       time to keep the page open after load (default 3000)
  stdout             "<RESULT_MARKER><json>" exactly once

The worker never receives API keys. Everything it learns is treated as
untrusted data by the host.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import ipaddress
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from playwright.sync_api import Error as PWError
from playwright.sync_api import sync_playwright

RESULT_MARKER = "@@IOC_RESULT@@"
OUT_DIR = Path(os.environ.get("OUT_DIR", "/tmp/out"))
NAV_TIMEOUT_MS = int(os.environ.get("NAV_TIMEOUT_MS", "20000"))
DWELL_MS = int(os.environ.get("DWELL_MS", "3000"))
MAX_DOWNLOAD_BYTES = int(os.environ.get("MAX_DOWNLOAD_BYTES", str(25 * 1024 * 1024)))
USER_AGENT = os.environ.get(
    "SANDBOX_UA",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
)

events: list[dict] = []


def emit(kind: str, **data) -> None:
    """Telemetry event (goes into the result, rendered later as the Containment Log)."""
    events.append({"t": round(time.time(), 3), "kind": kind, **data})


# --------------------------------------------------------------------------- #
# Containment self-probe: prove from the inside that sensitive targets are
# unreachable. These are the targets an attacker-controlled page would try.
# --------------------------------------------------------------------------- #
def default_gateway() -> str | None:
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if parts[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
    except Exception:
        return None
    return None


def tcp_probe(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "REACHABLE"
    except socket.timeout:
        return "blocked(timeout)"
    except OSError as exc:
        return f"blocked({exc.strerror or exc.__class__.__name__})"


def containment_probe() -> list[dict]:
    targets = [
        ("cloud-metadata", "169.254.169.254", 80),
        ("rfc1918-10/8", "10.0.0.1", 80),
        ("rfc1918-192.168/16", "192.168.0.1", 80),
    ]
    gw = default_gateway()
    if gw:
        targets.append(("docker-host-ssh", gw, 22))
        targets.append(("docker-host-api", gw, 8000))
    results = []
    for name, host, port in targets:
        status = tcp_probe(host, port)
        results.append({"target": name, "addr": f"{host}:{port}", "status": status})
        emit("containment_probe", target=name, addr=f"{host}:{port}", status=status)
    return results


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def b64_gzip(data: bytes) -> str:
    return base64.b64encode(gzip.compress(data, compresslevel=6)).decode()


DOM_SIGNALS_JS = r"""
() => {
  const abs = (u) => { try { return new URL(u, location.href).href } catch { return null } };
  const forms = [...document.forms].map(f => ({
    action: abs(f.getAttribute('action') || location.href),
    method: (f.method || 'get').toLowerCase(),
    has_password: !!f.querySelector('input[type=password]'),
    inputs: [...f.querySelectorAll('input')].slice(0, 25).map(i => ({
      type: (i.type || 'text').toLowerCase(), name: i.name || null
    })),
  }));
  const loosePassword = document.querySelectorAll('input[type=password]').length;
  const scripts = [...document.scripts].map(s => s.src ? abs(s.src) : null).filter(Boolean);
  const iframes = [...document.querySelectorAll('iframe')].map(i => abs(i.src)).filter(Boolean);
  const links = [...document.querySelectorAll('a[href]')].slice(0, 300).map(a => abs(a.getAttribute('href'))).filter(Boolean);
  const icon = document.querySelector('link[rel~="icon"]');
  const metaRefresh = document.querySelector('meta[http-equiv="refresh" i]');
  return {
    title: document.title || null,
    lang: document.documentElement.lang || null,
    forms, password_fields: loosePassword, scripts, iframes, links,
    favicon: icon ? abs(icon.getAttribute('href')) : abs('/favicon.ico'),
    meta_refresh: metaRefresh ? metaRefresh.getAttribute('content') : null,
    // Visible text is UNTRUSTED (may contain prompt injection). Capped and returned as data.
    text_excerpt: (document.body ? document.body.innerText : '').slice(0, 4000),
  };
}
"""


# --------------------------------------------------------------------------- #
# Main investigation
# --------------------------------------------------------------------------- #
def investigate(url: str) -> dict:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    har_path = OUT_DIR / "session.har"
    started = time.time()
    emit("sandbox_start", url=url, pid=os.getpid(), uid=os.getuid())

    result: dict = {
        "input_url": url,
        "final_url": None,
        "status": None,
        "redirect_chain": [],
        "requests": [],
        "failed_requests": [],
        "hosts": [],
        "server_ips": [],
        "tls": None,
        "downloads": [],
        "console": [],
        "dom": None,
        "screenshot_png_b64": None,
        "har_gz_b64": None,
        "containment": containment_probe(),
        "errors": [],
    }

    seen_hosts: set[str] = set()
    server_ips: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            # The container (+ gVisor) IS the sandbox; Chromium's own setuid/userns
            # sandbox cannot run with --cap-drop=ALL + no-new-privileges.
            chromium_sandbox=False,
            args=[
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--metrics-recording-only",
                "--mute-audio",
            ],
        )
        context = browser.new_context(
            user_agent=USER_AGENT,
            viewport={"width": 1366, "height": 850},
            ignore_https_errors=True,  # we WANT to see sites with bad certs
            accept_downloads=True,
            java_script_enabled=True,
            record_har_path=str(har_path),
            record_har_content="omit",  # metadata only, never store payload bodies
            service_workers="block",
        )
        page = context.new_page()

        def on_request(req):
            h = host_of(req.url)
            if h:
                seen_hosts.add(h)
            if len(result["requests"]) < 500:
                result["requests"].append(
                    {"method": req.method, "url": req.url[:2000], "type": req.resource_type}
                )

        def on_response(resp):
            try:
                addr = resp.server_addr()
                if addr and addr.get("ipAddress"):
                    server_ips.add(addr["ipAddress"])
            except PWError:
                pass

        def on_failed(req):
            err = req.failure or "unknown"
            result["failed_requests"].append({"url": req.url[:2000], "error": err})
            emit("request_failed", url=req.url[:300], error=err)

        def on_console(msg):
            if len(result["console"]) < 100:
                result["console"].append({"type": msg.type, "text": msg.text[:500]})

        def on_download(dl):
            info = {"suggested_filename": dl.suggested_filename, "url": dl.url[:2000]}
            try:
                path = dl.path()  # lands in tmpfs (noexec)
                size = os.path.getsize(path)
                info["size"] = size
                if size <= MAX_DOWNLOAD_BYTES:
                    h = hashlib.sha256()
                    md5 = hashlib.md5()
                    with open(path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(65536), b""):
                            h.update(chunk)
                            md5.update(chunk)
                    info["sha256"] = h.hexdigest()
                    info["md5"] = md5.hexdigest()
                os.remove(path)
            except Exception as exc:
                info["error"] = str(exc)
            result["downloads"].append(info)
            emit("download_captured", **{k: v for k, v in info.items() if k != "url"})

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("requestfailed", on_failed)
        page.on("console", on_console)
        page.on("download", on_download)

        main_response = None
        try:
            main_response = page.goto(url, wait_until="load", timeout=NAV_TIMEOUT_MS)
        except PWError as exc:
            msg = str(exc).splitlines()[0]
            result["errors"].append({"stage": "navigate", "error": msg})
            emit("navigation_error", error=msg)

        # Let JS-driven redirects / delayed payloads happen.
        try:
            page.wait_for_timeout(DWELL_MS)
        except PWError:
            pass

        if main_response is not None:
            result["status"] = main_response.status
            # Walk the redirect chain backwards from the final request.
            chain = []
            req = main_response.request
            while req is not None:
                chain.append(req.url)
                req = req.redirected_from
            result["redirect_chain"] = list(reversed(chain))
            try:
                sec = main_response.security_details()
                if sec:
                    result["tls"] = sec
            except PWError:
                pass

        result["final_url"] = page.url
        try:
            result["dom"] = page.evaluate(DOM_SIGNALS_JS)
        except PWError as exc:
            result["errors"].append({"stage": "dom", "error": str(exc).splitlines()[0]})

        try:
            png = page.screenshot(full_page=False, type="png")
            result["screenshot_png_b64"] = base64.b64encode(png).decode()
            emit("screenshot_captured", bytes=len(png))
        except PWError as exc:
            result["errors"].append({"stage": "screenshot", "error": str(exc).splitlines()[0]})

        context.close()  # flushes HAR
        browser.close()

    if har_path.exists():
        raw = har_path.read_bytes()
        result["har_gz_b64"] = b64_gzip(raw)
        emit("har_captured", bytes=len(raw))

    result["hosts"] = sorted(seen_hosts)
    result["server_ips"] = sorted(server_ips)  # IPs we actually got a response from
    result["ip_literal_hosts"] = sorted(h for h in seen_hosts if is_ip(h))  # page tried raw IPs
    result["duration_s"] = round(time.time() - started, 2)
    emit("sandbox_done", duration_s=result["duration_s"])
    result["events"] = events
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print(RESULT_MARKER + json.dumps({"fatal": "usage: worker.py <url>"}))
        return 2
    url = sys.argv[1].strip()
    if urlparse(url).scheme not in ("http", "https"):
        print(RESULT_MARKER + json.dumps({"fatal": "only http/https URLs are allowed"}))
        return 2
    try:
        result = investigate(url)
    except Exception as exc:  # never crash without a result line
        result = {"fatal": f"{exc.__class__.__name__}: {exc}", "events": events}
    sys.stdout.write(RESULT_MARKER + json.dumps(result, default=str) + "\n")
    sys.stdout.flush()
    return 0 if "fatal" not in result else 1


if __name__ == "__main__":
    raise SystemExit(main())
