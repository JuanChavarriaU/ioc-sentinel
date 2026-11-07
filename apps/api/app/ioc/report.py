"""
Analyst-facing report built DETERMINISTICALLY from the evidence (heuristic signals + IoCs) and the agent verdict.

Nothing here calls the LLM: the risk level, ATT&CK mapping, blocklist and recommended actions are reproducible.
ATT&CK mappings are indicative (derived from observed behavior), not an attribution.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_ORDER = {"benign": 0, "no_indicators": 0, "inconclusive": 1, "suspicious": 2, "malicious": 3}
_NAME = {0: "benign", 1: "inconclusive", 2: "suspicious", 3: "malicious"}

TECHNIQUES = {
    "credential_harvest_cross_domain": ("T1598.003", "Phishing for Information: Spearphishing Link"),
    "automatic_download": ("T1189", "Drive-by Compromise"),
}

ACTIONS = {
    "credential_harvest_cross_domain": "Block the credential-collection host at DNS/proxy and reset the credentials of any user who submitted data to this page. Notify the impersonated brand.",
    "automatic_download": "Block the download URL and hunt endpoints for the SHA-256 listed below. Do not execute the file.",
    "internal_network_probe": "The page tried to reach cloud-metadata/internal addresses (SSRF-style). Confirm browsers used for triage cannot reach metadata endpoints or internal ranges.",
    "raw_ip_requests": "Review traffic to the raw IP hosts; kits and C2 often avoid domain names.",
}


def _is_private(value: str) -> bool:
    try:
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def build_report(agent: dict, heuristic: dict, iocs: list[dict], target_url: str) -> dict:
    a_level = _ORDER.get(str(agent.get("verdict", "inconclusive")).lower(), 1)
    h_level = _ORDER.get(str(heuristic.get("verdict", "no_indicators")).lower(), 0)
    level = max(a_level, h_level)
    confidence = float(agent.get("confidence") or 0)
    agree = (a_level == h_level) or (a_level == 0 and h_level == 0)
    score = int(heuristic.get("score") or 0)
    signals = {s["signal"]: s for s in heuristic.get("signals", [])}

    if level == 3:
        risk = "critical" if score >= 80 else "high"
    elif level == 2:
        risk = "medium"
    elif level == 1:
        risk = "low"
    else:
        risk = "info"

    review_reasons = []
    if not agree:
        review_reasons.append(f"agent says {agent.get('verdict')} but heuristics say {heuristic.get('verdict')}")
    if confidence and confidence < 0.6:
        review_reasons.append(f"low agent confidence ({confidence:.2f})")
    if level == 1:
        review_reasons.append("agent could not reach a verdict")

    techniques = []
    for name, (tid, tname) in TECHNIQUES.items():
        if name in signals:
            techniques.append({"id": tid, "name": tname, "evidence": signals[name]["detail"]})
    probe = signals.get("internal_network_probe")
    if probe:
        if "169.254" in probe["detail"]:
            techniques.append({"id": "T1552.005", "name": "Unsecured Credentials: Cloud Instance Metadata API",
                               "evidence": probe["detail"]})
        else:
            techniques.append({"id": "T1046", "name": "Network Service Discovery", "evidence": probe["detail"]})

    target_host = _host(target_url)
    blocklist: list[dict] = []
    seen: set[str] = set()

    def add(kind: str, value: str, reason: str) -> None:
        if value and value not in seen:
            seen.add(value)
            blocklist.append({"type": kind, "value": value, "reason": reason})

    if level >= 2:
        add("domain", target_host, "target (verify it is not a shared platform before blocking the whole domain)")
        for i in iocs:
            if i["type"] == "credential-form":
                h = _host(i["value"])
                if h:
                    add("domain", h, "receives submitted credentials")
            elif i["type"] == "sha256":
                add("sha256", i["value"], f"automatic download {i.get('note') or ''}".strip())
            elif i["type"] == "domain" and i["value"] != target_host:
                add("domain", i["value"], "contacted by the page (review before blocking)")
            elif i["type"] == "ipv4" and not _is_private(i["value"]):
                add("ip", i["value"], "raw-IP request")

    actions = [ACTIONS[k] for k in ACTIONS if k in signals]
    if agent.get("prompt_injection_detected"):
        actions.append("The page carried instructions aimed at AI analysts. Keep AI triage in untrusted-data mode and report the page.")
    if level >= 2:
        actions.append("Add the blocklist indicators to SIEM/EDR watchlists and search historical logs for them.")
    else:
        actions.append("No blocking action indicated. Re-scan if the site changes.")

    return {
        "risk_level": risk,
        "consensus": {"verdict": _NAME[level], "agent": agent.get("verdict"), "heuristic": heuristic.get("verdict"),
                      "agree": agree},
        "review_required": bool(review_reasons),
        "review_reasons": review_reasons,
        "techniques": techniques,
        "blocklist": blocklist,
        "recommended_actions": actions,
    }
