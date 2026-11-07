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
    agent_model: str = _env("AGENT_MODEL", "qwen3.8-27b")

    # --- Visual verification (Pattern B: a vision model verifies the screenshot) ---
    vision_enabled: bool = _env("VISION_ENABLED", "1") not in ("0", "false", "no")
    vision_model: str | None = _env("VISION_MODEL")  # defaults to AGENT_MODEL (qwen3.8-27b supports vision)
    vision_timeout_s: float = float(_env("VISION_TIMEOUT_S", "20"))

    # --- Host-side threat intel (optional; tools degrade gracefully without keys) ---
    abusech_auth_key: str | None = _env("ABUSECH_AUTH_KEY")
    agent_max_steps: int = int(_env("AGENT_MAX_STEPS", "6"))
    agent_max_scans: int = int(_env("AGENT_MAX_SCANS", "2"))

    # --- Public-demo abuse protection (per client IP; 0 disables) ---
    rate_limit_per_ip: int = int(_env("RATE_LIMIT_PER_IP", "5"))
    rate_window_s: int = int(_env("RATE_WINDOW_S", "600"))

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
