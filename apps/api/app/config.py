"""Host-side configuration. Secrets live ONLY here (env vars on the VM), never in the sandbox."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    return value if value not in ("", None) else default


@dataclass(frozen=True)
class Settings:
    # --- Vultr Serverless Inference (host only) ---
    inference_base_url: str = _env("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1")
    inference_api_key: str | None = _env("VULTR_INFERENCE_API_KEY")
    agent_model: str = _env("AGENT_MODEL", "kimi-k2-instruct")

    # --- Sandbox ---
    sandbox_image: str = _env("SANDBOX_IMAGE", "ioc-sentinel/sandbox-browser:latest")
    sandbox_network: str = _env("SANDBOX_NETWORK", "ioc-jail")
    # "runsc" for gVisor, None for the default runc runtime.
    sandbox_runtime: str | None = _env("SANDBOX_RUNTIME")
    sandbox_user: str = _env("SANDBOX_USER", "pwuser")
    sandbox_timeout_s: int = int(_env("SANDBOX_TIMEOUT_S", "60"))
    sandbox_mem: str = _env("SANDBOX_MEM", "1g")
    sandbox_cpus: float = float(_env("SANDBOX_CPUS", "1.0"))
    # Chromium is thread-heavy and pids_limit counts threads; 64 is too low for it.
    sandbox_pids: int = int(_env("SANDBOX_PIDS", "512"))
    sandbox_dns: list[str] = field(
        default_factory=lambda: (_env("SANDBOX_DNS", "1.1.1.1,9.9.9.9") or "").split(",")
    )
    nav_timeout_ms: int = int(_env("NAV_TIMEOUT_MS", "20000"))
    dwell_ms: int = int(_env("DWELL_MS", "3000"))

    # --- Storage ---
    data_dir: Path = Path(_env("DATA_DIR", str(Path(__file__).resolve().parents[3] / "data")))


settings = Settings()
