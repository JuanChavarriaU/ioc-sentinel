"""
Deterministic IoC extraction + heuristic risk score from sandbox observations.

This does NOT depend on the LLM: the evidence list and score are reproducible, and the agent's
verdict is shown next to it. IoC categories follow the usual forensic grouping
(network / file / behavioral).
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

INTERNAL_PREFIXES = ("169.254.", "10.", "192.168.", "127.", "172.16.", "172.17.", "172.30.")


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _registrable(host: str) -> str:
    """Cheap eTLD+1 approximation (last two labels) - enough to spot cross-domain form posts."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def extract_iocs(obs: dict) -> list[dict]:
    """Typed, de-duplicated IoCs with the evidence field they came from."""
    iocs: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, category: str, source: str, note: str = "") -> None:
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        iocs.append({"type": kind, "value": value, "category": category, "source": source, "note": note})

    final_url = obs.get("final_url") or ""
    if final_url and not final_url.startswith("chrome-error"):
        add("url", final_url, "network", "final_url", "final landing URL")
    for hop in obs.get("redirect_chain") or []:
        add("url", hop, "network", "redirect_chain", "redirect hop")
    for h in obs.get("hosts") or []:
        add("ipv4" if _is_ip(h) else "domain", h, "network", "hosts", "contacted by the page")
    for ip in obs.get("server_ips") or []:
        add("ip", ip, "network", "server_ips", "server that answered")
    tls = obs.get("tls") or {}
    if tls:
        add("tls-cert", f"{tls.get('issuer', '?')} | {tls.get('subjectName', '?')}", "network", "tls",
            f"valid {tls.get('validFrom')} -> {tls.get('validTo')}")
    for d in obs.get("downloads") or []:
        if d.get("sha256"):
            add("sha256", d["sha256"], "file", "downloads", d.get("suggested_filename") or "")
        if d.get("md5"):
            add("md5", d["md5"], "file", "downloads", d.get("suggested_filename") or "")
    dom = obs.get("dom") or {}
    page_domain = _registrable(_host(final_url))
    for f in dom.get("forms") or []:
        if f.get("has_password"):
            action = f.get("action") or ""
            cross = _registrable(_host(action)) != page_domain
            add("credential-form", action, "behavioral", "dom.forms",
                "password form posting to a DIFFERENT domain" if cross else "password form")
    for fr in dom.get("iframes") or []:
        add("iframe", fr, "behavioral", "dom.iframes", "embedded frame")
    return iocs


def score(obs: dict) -> dict:
    """Additive heuristic. Returns {score, verdict, signals:[{signal, points, detail}]}."""
    signals: list[dict] = []

    def sig(name: str, pts: int, detail: str) -> None:
        signals.append({"signal": name, "points": pts, "detail": detail})

    dom = obs.get("dom") or {}
    final_url = obs.get("final_url") or ""
    page_domain = _registrable(_host(final_url))

    for f in dom.get("forms") or []:
        if f.get("has_password"):
            if _registrable(_host(f.get("action") or "")) != page_domain:
                sig("credential_harvest_cross_domain", 45, f"password form posts to {f.get('action')}")
            else:
                sig("password_form", 10, "page asks for a password")
    if obs.get("downloads"):
        sig("automatic_download", 30, f"{len(obs['downloads'])} file(s) downloaded without interaction")
    if obs.get("ip_literal_hosts"):
        sig("raw_ip_requests", 15, f"requests to raw IPs: {', '.join(obs['ip_literal_hosts'][:5])}")
    chain = obs.get("redirect_chain") or []
    if len(chain) > 3:
        sig("long_redirect_chain", 10, f"{len(chain)} hops")
    internal = [r["url"] for r in (obs.get("requests") or []) + (obs.get("failed_requests") or [])
                if _host(r.get("url", "")) .startswith(INTERNAL_PREFIXES)]
    if internal:
        sig("internal_network_probe", 35, f"page tried internal/metadata targets, e.g. {internal[0][:80]}")
    if dom.get("meta_refresh"):
        sig("meta_refresh", 5, f"meta refresh: {dom['meta_refresh'][:80]}")
    if (obs.get("tls") is None) and final_url.startswith("http://"):
        sig("no_tls", 5, "final page served without TLS")

    total = min(100, sum(s["points"] for s in signals))
    verdict = "malicious" if total >= 60 else "suspicious" if total >= 25 else "no_indicators"
    return {"score": total, "verdict": verdict, "signals": signals}
