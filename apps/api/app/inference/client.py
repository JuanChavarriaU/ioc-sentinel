"""Thin client for Vultr Serverless Inference (OpenAI-compatible). Host-side only."""

from __future__ import annotations

import httpx

from ..config import settings


class InferenceClient:
    def __init__(self, api_key: str | None = None, base_url: str | None = None, model: str | None = None):
        key = api_key or settings.inference_api_key
        if not key:
            raise RuntimeError("VULTR_INFERENCE_API_KEY is not configured")
        self.model = model or settings.agent_model
        self._http = httpx.Client(
            base_url=base_url or settings.inference_base_url,
            headers={"Authorization": f"Bearer {key}"},
            timeout=120,
        )

    def chat(self, messages: list[dict], *, tools: list[dict] | None = None, **extra) -> dict:
        payload = {"model": self.model, "messages": messages, **extra}
        if tools:
            payload["tools"] = tools
            payload.setdefault("tool_choice", "auto")
        r = self._http.post("/chat/completions", json=payload)
        r.raise_for_status()
        return r.json()

    def models(self) -> list[dict]:
        r = self._http.get("/models")
        r.raise_for_status()
        return r.json().get("data", [])
