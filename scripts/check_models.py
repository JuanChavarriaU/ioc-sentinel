#!/usr/bin/env python3
"""
Day-1 reality check for Vultr Serverless Inference.

  python scripts/check_models.py              # list models
  python scripts/check_models.py --probe      # + test tool calling & vision per chat model
  python scripts/check_models.py --probe --model kimi-k2-instruct

Reads VULTR_INFERENCE_API_KEY (and optional VULTR_INFERENCE_BASE_URL) from env or .env.
Writes docs/models.json so the team has the verified capability matrix in the repo.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]

# 8x8 red PNG for the vision probe.
RED_PNG = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAEklEQVR4nGP4z8CAFWEXHbQSACj/P8Fu7N9hAAAAAElFTkSuQmCC"

TOOL = {
    "type": "function",
    "function": {
        "name": "lookup_domain_reputation",
        "description": "Look up threat-intel reputation for a domain.",
        "parameters": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
}


def load_dotenv() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def chat(client: httpx.Client, model: str, messages: list, **extra) -> tuple[int, dict, float]:
    t0 = time.time()
    r = client.post("/chat/completions", json={"model": model, "messages": messages, "max_tokens": 200, **extra})
    dt = time.time() - t0
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:300]}
    return r.status_code, body, dt


def probe_tools(client, model) -> dict:
    code, body, dt = chat(
        client,
        model,
        [{"role": "user", "content": "Check the reputation of the domain login-microsoft-verify.top"}],
        tools=[TOOL],
        tool_choice="auto",
    )
    calls = (((body.get("choices") or [{}])[0].get("message") or {}).get("tool_calls")) if code == 200 else None
    return {"http": code, "tool_call": bool(calls), "latency_s": round(dt, 2),
            "detail": calls[0]["function"] if calls else str(body)[:200]}


def probe_vision(client, model) -> dict:
    code, body, dt = chat(
        client,
        model,
        [{"role": "user", "content": [
            {"type": "text", "text": "What single color is this image? Answer with one word."},
            {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{RED_PNG}"}},
        ]}],
    )
    text = ""
    if code == 200:
        text = (((body.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
    return {"http": code, "vision": "red" in text.lower(), "latency_s": round(dt, 2),
            "detail": text[:80] if text else str(body)[:200]}


def main() -> int:
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", action="store_true", help="test tool calling + vision")
    ap.add_argument("--model", action="append", help="limit probes to these model ids")
    args = ap.parse_args()

    key = os.environ.get("VULTR_INFERENCE_API_KEY")
    if not key:
        print("VULTR_INFERENCE_API_KEY not set (env or .env)")
        return 2
    base = os.environ.get("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1")
    client = httpx.Client(base_url=base, headers={"Authorization": f"Bearer {key}"}, timeout=60)

    r = client.get("/models")
    if r.status_code != 200:
        print(f"GET /models -> {r.status_code}: {r.text[:300]}")
        return 1
    models = r.json().get("data", [])
    print(f"{len(models)} models available at {base}\n")
    for m in models:
        print(f"  - {m.get('id'):<45} {json.dumps({k: v for k, v in m.items() if k not in ('id', 'object')})[:90]}")

    report = {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "base_url": base,
              "models": models, "probes": {}}

    if args.probe:
        ids = args.model or [m["id"] for m in models
                             if not any(x in m["id"].lower() for x in ("embed", "whisper", "tts", "flux", "stable", "sdxl"))]
        print("\nProbing (tool calling / vision):")
        for mid in ids:
            t = probe_tools(client, mid)
            v = probe_vision(client, mid)
            report["probes"][mid] = {"tools": t, "vision": v}
            print(f"  {mid:<45} tools={'YES' if t['tool_call'] else 'no ':<3} ({t['latency_s']}s)  "
                  f"vision={'YES' if v['vision'] else 'no ':<3} ({v['latency_s']}s)")

    out = ROOT / "docs" / "models.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"\nSaved -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
