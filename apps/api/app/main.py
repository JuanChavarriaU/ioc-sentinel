"""
IoC Sentinel API (Day 1): submit a URL, get sandbox observations + containment log.
Day 2 adds the agent loop (Vultr Serverless Inference + host-side threat-intel tools).

  uvicorn app.main:app --app-dir apps/api --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .config import settings
from .sandbox.runner import run_in_sandbox, save_artifacts
from .sandbox.url_guard import UnsafeTarget, normalize_target

app = FastAPI(title="IoC Sentinel", version="0.1.0")
SCANS = settings.data_dir / "scans"


class ScanRequest(BaseModel):
    url: str


def _scan_dir(scan_id: str) -> Path:
    if not scan_id.isalnum():
        raise HTTPException(400, "bad scan id")
    d = SCANS / scan_id
    if not d.exists():
        raise HTTPException(404, "scan not found")
    return d


@app.get("/healthz")
def healthz():
    return {"ok": True, "sandbox_image": settings.sandbox_image,
            "runtime": settings.sandbox_runtime or "runc", "network": settings.sandbox_network}


@app.post("/api/scans")
async def create_scan(req: ScanRequest):
    try:
        target = normalize_target(req.url)
    except UnsafeTarget as exc:
        raise HTTPException(400, str(exc))
    run = await run_in_threadpool(run_in_sandbox, target)
    save_artifacts(run)
    return json.loads((SCANS / run.scan_id / "result.json").read_text())


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    return json.loads((_scan_dir(scan_id) / "result.json").read_text())


@app.get("/api/scans/{scan_id}/screenshot.png")
def get_screenshot(scan_id: str):
    p = _scan_dir(scan_id) / "screenshot.png"
    if not p.exists():
        raise HTTPException(404, "no screenshot")
    return FileResponse(p, media_type="image/png")


@app.get("/api/scans/{scan_id}/session.har")
def get_har(scan_id: str):
    p = _scan_dir(scan_id) / "session.har"
    if not p.exists():
        raise HTTPException(404, "no HAR")
    return FileResponse(p, media_type="application/json", filename=f"{scan_id}.har")
