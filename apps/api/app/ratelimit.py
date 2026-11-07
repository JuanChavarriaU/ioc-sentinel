"""
Per-IP sliding-window rate limiter (in-memory; the API runs as a single uvicorn process).

The API listens on loopback only, behind Caddy, which sets X-Forwarded-For to the real client.
We read the LAST entry (the one appended by our own proxy), so a client cannot spoof its way
out of the limit by sending its own X-Forwarded-For header.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from .config import settings

_HITS: dict[str, deque[float]] = defaultdict(deque)
_MAX_TRACKED_IPS = 10_000


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[-1].strip() or "unknown"
    return request.client.host if request.client else "unknown"


def enforce(request: Request) -> None:
    """Raise 429 (with Retry-After) when this IP exceeded its quota. Call after cheap validation."""
    limit, window = settings.rate_limit_per_ip, settings.rate_window_s
    if limit <= 0:
        return
    now = time.time()
    ip = client_ip(request)
    hits = _HITS[ip]
    while hits and now - hits[0] > window:
        hits.popleft()
    if len(hits) >= limit:
        retry = int(window - (now - hits[0])) + 1
        raise HTTPException(
            429,
            f"Rate limit: {limit} investigations per {window // 60} min per IP. Retry in {retry}s.",
            headers={"Retry-After": str(retry)},
        )
    hits.append(now)
    if len(_HITS) > _MAX_TRACKED_IPS:  # bound memory: drop idle entries
        for k in [k for k, v in _HITS.items() if not v or now - v[-1] > window]:
            _HITS.pop(k, None)
