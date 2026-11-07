"""
Agent tools. They run on the HOST (trusted side) and may use credentials; the only tool that
touches the suspicious target, `scan_url`, delegates to the credential-less sandbox.

Everything returned to the model is wrapped as UNTRUSTED data by the loop.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field

import httpx

from ..config import settings
from ..sandbox.runner import SandboxRun, run_in_sandbox, save_artifacts
from ..sandbox.url_guard import UnsafeTarget

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "scan_url",
            "description": "Visit a URL inside the isolated sandbox browser and return observations "
                           "(redirects, contacted hosts, TLS, forms, downloads, page text excerpt). "
                           "Limited number of calls per investigation.",
            "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dns_lookup",
            "description": "Resolve a domain to its IPv4/IPv6 addresses from the host.",
            "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cert_transparency",
            "description": "Query crt.sh certificate transparency logs for a domain: how many certs, "
                           "related names, first-seen date (young domains are a phishing signal).",
            "parameters": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "urlhaus_host",
            "description": "Check a host against abuse.ch URLhaus (known malware distribution). "
                           "Returns 'skipped' if no API key is configured.",
            "parameters": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
        },
    },
]


_CRT_FUTURES: dict[str, Future] = {}
_CRT_STARTED: dict[str, float] = {}
_CRT_LOCK = threading.Lock()
_CRT_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="crtsh")
_CRT_TTL_S = 3600


@dataclass
class ToolContext:
    runs: list[SandboxRun] = field(default_factory=list)
    scan_ids: list[str] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)  # tools may run in parallel
    scans_reserved: int = 0

    @property
    def last_obs(self) -> dict:
        return self.runs[-1].result if self.runs else {}


def _clean_domain(value: str) -> str | None:
    v = (value or "").strip().lower().rstrip(".")
    return v if DOMAIN_RE.match(v) else None


def _condense(run: SandboxRun) -> dict:
    o = run.result or {}
    dom = o.get("dom") or {}
    tls = o.get("tls") or {}
    return {
        "scan_id": run.scan_id,
        "verdict": run.verdict,
        "final_url": o.get("final_url"),
        "status": o.get("status"),
        "redirect_chain": o.get("redirect_chain"),
        "hosts": o.get("hosts"),
        "server_ips": o.get("server_ips"),
        "ip_literal_hosts": o.get("ip_literal_hosts"),
        "tls": {k: tls.get(k) for k in ("issuer", "subjectName", "validFrom", "validTo", "protocol")} if tls else None,
        "downloads": [{k: d.get(k) for k in ("suggested_filename", "size", "sha256")} for d in o.get("downloads", [])],
        "title": dom.get("title"),
        "forms": [{"action": f.get("action"), "has_password": f.get("has_password")} for f in dom.get("forms", [])][:5],
        "iframes": (dom.get("iframes") or [])[:5],
        "scripts_count": len(dom.get("scripts") or []),
        "failed_requests": [r.get("url") for r in (o.get("failed_requests") or [])][:8],
        "containment": [{"target": c["target"], "status": c["status"]} for c in o.get("containment", [])],
        "page_text_excerpt": (dom.get("text_excerpt") or "")[:1500],
        "errors": o.get("errors"),
    }


def scan_url(ctx: ToolContext, url: str) -> dict:
    with ctx.lock:  # reserve a slot atomically (tool calls can run in parallel)
        if ctx.scans_reserved >= settings.agent_max_scans:
            return {"error": f"scan limit reached ({settings.agent_max_scans} per investigation)"}
        ctx.scans_reserved += 1
    try:
        run = run_in_sandbox(url)  # normalize_target() inside rejects internal/unsafe targets
    except UnsafeTarget as exc:
        return {"error": f"target refused by URL guard: {exc}"}
    save_artifacts(run)
    with ctx.lock:
        ctx.runs.append(run)
        ctx.scan_ids.append(run.scan_id)
    return _condense(run)


def dns_lookup(ctx: ToolContext, domain: str) -> dict:
    d = _clean_domain(domain)
    if not d:
        return {"error": "invalid domain"}
    try:
        infos = socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return {"domain": d, "resolves": False, "error": str(exc)}
    return {"domain": d, "resolves": True, "addresses": sorted({i[4][0] for i in infos})}


def _crt_fetch(d: str) -> dict:
    try:
        # crt.sh is often slow: a short timeout keeps the investigation fast (it was 25 s of a 34 s run).
        r = httpx.get("https://crt.sh/", params={"q": d, "output": "json"}, timeout=8)
        r.raise_for_status()
        rows = r.json()
    except Exception as exc:  # flaky service; never crash or stall the investigation
        return {"domain": d, "error": f"crt.sh unavailable ({exc.__class__.__name__}); not a verdict signal"}
    names: set[str] = set()
    for row in rows:
        names.update(n.strip().lower() for n in str(row.get("name_value", "")).splitlines())
    firsts = sorted(str(r.get("not_before", "")) for r in rows if r.get("not_before"))
    return {"domain": d, "certificates": len(rows), "first_seen": firsts[0] if firsts else None,
            "latest_seen": firsts[-1] if firsts else None, "related_names": sorted(names)[:20]}


def _crt_future(d: str) -> Future:
    """One in-flight/cached lookup per domain, shared by the prefetch and the model's own tool call."""
    with _CRT_LOCK:
        fut = _CRT_FUTURES.get(d)
        if fut is not None and (not fut.done() or time.time() - _CRT_STARTED[d] < _CRT_TTL_S):
            return fut
        fut = _CRT_POOL.submit(_crt_fetch, d)
        _CRT_FUTURES[d], _CRT_STARTED[d] = fut, time.time()
        return fut


def prefetch_cert_transparency(host: str) -> None:
    """Start the slow crt.sh lookup while the sandbox is still scanning."""
    d = _clean_domain(host)
    if d:
        _crt_future(d)


def cert_transparency(ctx: ToolContext, domain: str) -> dict:
    d = _clean_domain(domain)
    if not d:
        return {"error": "invalid domain"}
    try:
        return _crt_future(d).result(timeout=9)
    except Exception:
        return {"domain": d, "error": "crt.sh lookup timed out; not a verdict signal"}


def urlhaus_host(ctx: ToolContext, host: str) -> dict:
    h = _clean_domain(host) or (host if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or "") else None)
    if not h:
        return {"error": "invalid host"}
    if not settings.abusech_auth_key:
        return {"host": h, "skipped": "ABUSECH_AUTH_KEY not configured"}
    try:
        r = httpx.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": h},
                       headers={"Auth-Key": settings.abusech_auth_key}, timeout=20)
        r.raise_for_status()
        j = r.json()
    except Exception as exc:
        return {"host": h, "error": f"URLhaus unavailable: {exc.__class__.__name__}"}
    urls = j.get("urls") or []
    return {"host": h, "query_status": j.get("query_status"), "urls_count": j.get("url_count"),
            "blacklists": j.get("blacklists"), "sample": [{"url": u.get("url"), "threat": u.get("threat"),
                                                           "status": u.get("url_status")} for u in urls[:5]]}


DISPATCH = {"scan_url": scan_url, "dns_lookup": dns_lookup,
            "cert_transparency": cert_transparency, "urlhaus_host": urlhaus_host}
