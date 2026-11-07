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
    "credential_harvest_cross_domain": (
        "Block the credential-collection host at DNS/proxy and reset the credentials of any user who submitted data to this page. Notify the impersonated brand.",
        "Bloquea el host que recolecta credenciales en DNS/proxy y restablece las credenciales de quien haya enviado datos a esta página. Avisa a la marca suplantada."),
    "automatic_download": (
        "Block the download URL and hunt endpoints for the SHA-256 listed below. Do not execute the file.",
        "Bloquea la URL de descarga y busca en los equipos el SHA-256 listado abajo. No ejecutes el archivo."),
    "internal_network_probe": (
        "The page tried to reach cloud-metadata/internal addresses (SSRF-style). Confirm browsers used for triage cannot reach metadata endpoints or internal ranges.",
        "La página intentó alcanzar direcciones de metadata/internas (tipo SSRF). Confirma que los navegadores usados para triaje no alcanzan endpoints de metadata ni rangos internos."),
    "raw_ip_requests": (
        "Review traffic to the raw IP hosts; kits and C2 often avoid domain names.",
        "Revisa el tráfico hacia las IPs directas; los kits y el C2 suelen evitar nombres de dominio."),
}
ACTION_INJECTION = (
    "The page carried instructions aimed at AI analysts. Keep AI triage in untrusted-data mode and report the page.",
    "La página traía instrucciones dirigidas a analistas de IA. Mantén el triaje con IA en modo de datos no confiables y reporta la página.")
ACTION_WATCHLIST = (
    "Add the blocklist indicators to SIEM/EDR watchlists and search historical logs for them.",
    "Agrega los indicadores de la lista de bloqueo a las listas de vigilancia del SIEM/EDR y busca coincidencias en logs históricos.")
ACTION_NONE = (
    "No blocking action indicated. Re-scan if the site changes.",
    "No se indica ningún bloqueo. Vuelve a escanear si el sitio cambia.")


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

    review_reasons: list[tuple[str, str]] = []
    if not agree:
        review_reasons.append((f"agent says {agent.get('verdict')} but heuristics say {heuristic.get('verdict')}",
                               f"el agente dice {agent.get('verdict')} pero la heurística dice {heuristic.get('verdict')}"))
    if confidence and confidence < 0.6:
        review_reasons.append((f"low agent confidence ({confidence:.2f})", f"baja confianza del agente ({confidence:.2f})"))
    if level == 1:
        review_reasons.append(("agent could not reach a verdict", "el agente no logró emitir un veredicto"))

    techniques = []
    for name, (tid, tname) in TECHNIQUES.items():
        if name in signals:
            techniques.append({"id": tid, "name": tname, "evidence": signals[name]["detail"],
                               "evidence_es": signals[name].get("detail_es", signals[name]["detail"])})
    probe = signals.get("internal_network_probe")
    if probe:
        if "169.254" in probe["detail"]:
            techniques.append({"id": "T1552.005", "name": "Unsecured Credentials: Cloud Instance Metadata API",
                               "evidence": probe["detail"], "evidence_es": probe.get("detail_es", probe["detail"])})
        else:
            techniques.append({"id": "T1046", "name": "Network Service Discovery", "evidence": probe["detail"],
                               "evidence_es": probe.get("detail_es", probe["detail"])})

    target_host = _host(target_url)
    blocklist: list[dict] = []
    seen: set[str] = set()

    def add(kind: str, value: str, reason: str, reason_es: str) -> None:
        if value and value not in seen:
            seen.add(value)
            blocklist.append({"type": kind, "value": value, "reason": reason, "reason_es": reason_es})

    if level >= 2:
        add("domain", target_host, "target (verify it is not a shared platform before blocking the whole domain)",
            "objetivo (verifica que no sea una plataforma compartida antes de bloquear todo el dominio)")
        for i in iocs:
            if i["type"] == "credential-form":
                h = _host(i["value"])
                if h:
                    add("domain", h, "receives submitted credentials", "recibe las credenciales enviadas")
            elif i["type"] == "sha256":
                note = i.get("note") or ""
                add("sha256", i["value"], f"automatic download {note}".strip(), f"descarga automática {note}".strip())
            elif i["type"] == "domain" and i["value"] != target_host:
                add("domain", i["value"], "contacted by the page (review before blocking)",
                    "contactado por la página (revisar antes de bloquear)")
            elif i["type"] == "ipv4" and not _is_private(i["value"]):
                add("ip", i["value"], "raw-IP request", "petición a IP directa")

    pairs = [ACTIONS[k] for k in ACTIONS if k in signals]
    if agent.get("prompt_injection_detected"):
        pairs.append(ACTION_INJECTION)
    pairs.append(ACTION_WATCHLIST if level >= 2 else ACTION_NONE)

    return {
        "risk_level": risk,
        "consensus": {"verdict": _NAME[level], "agent": agent.get("verdict"), "heuristic": heuristic.get("verdict"),
                      "agree": agree},
        "review_required": bool(review_reasons),
        "review_reasons": [r[0] for r in review_reasons],
        "review_reasons_es": [r[1] for r in review_reasons],
        "techniques": techniques,
        "blocklist": blocklist,
        "recommended_actions": [p[0] for p in pairs],
        "recommended_actions_es": [p[1] for p in pairs],
    }
