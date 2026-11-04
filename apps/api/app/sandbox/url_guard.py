"""Host-side input validation (defense in depth; the jail network is the real control)."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse, urlunparse


class UnsafeTarget(ValueError):
    pass


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeTarget("empty target")
    if "://" not in raw:
        raw = "http://" + raw  # bare domain -> let redirects take it to https
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeTarget(f"scheme not allowed: {parsed.scheme}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise UnsafeTarget("missing host")
    if parsed.username or parsed.password:
        raise UnsafeTarget("credentials in URL are not allowed")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise UnsafeTarget(f"non-public IP target refused: {ip}")
    if host in ("localhost",) or host.endswith((".localhost", ".internal", ".local")):
        raise UnsafeTarget(f"internal hostname refused: {host}")
    if len(raw) > 2048:
        raise UnsafeTarget("URL too long")
    return urlunparse(parsed._replace(fragment=""))
