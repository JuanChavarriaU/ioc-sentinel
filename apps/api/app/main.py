"""
IoC Sentinel API (Day 1): submit a URL, get sandbox observations + containment log.
Day 2 adds the agent loop (Vultr Serverless Inference + host-side threat-intel tools).

  uvicorn app.main:app --app-dir apps/api --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .agent.loop import investigate
from .config import settings
from .sandbox.runner import run_in_sandbox, save_artifacts
from .sandbox.url_guard import UnsafeTarget, normalize_target

app = FastAPI(title="IoC Sentinel", version="0.2.0")
SCANS = settings.data_dir / "scans"
INVESTIGATIONS = settings.data_dir / "investigations"


class ScanRequest(BaseModel):
    url: str


def _scan_dir(scan_id: str) -> Path:
    if not scan_id.isalnum():
        raise HTTPException(400, "bad scan id")
    d = SCANS / scan_id
    if not d.exists():
        raise HTTPException(404, "scan not found")
    return d


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(Path(__file__).parent / "static" / "index.html", media_type="text/html")


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


@app.post("/api/investigations")
async def create_investigation(req: ScanRequest):
    """Full agent run: LLM (Vultr Serverless Inference) + sandboxed scan + host-side threat intel."""
    try:
        target = normalize_target(req.url)
    except UnsafeTarget as exc:
        raise HTTPException(400, str(exc))
    try:
        result = await run_in_threadpool(investigate, target)
    except RuntimeError as exc:  # e.g. inference key not configured
        raise HTTPException(503, str(exc))
    inv_id = uuid.uuid4().hex[:12]
    result["investigation_id"] = inv_id
    d = INVESTIGATIONS / inv_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "investigation.json").write_text(json.dumps(result, indent=2, default=str))
    return result


@app.get("/api/investigations/{inv_id}")
def get_investigation(inv_id: str):
    if not inv_id.isalnum():
        raise HTTPException(400, "bad investigation id")
    p = INVESTIGATIONS / inv_id / "investigation.json"
    if not p.exists():
        raise HTTPException(404, "investigation not found")
    return json.loads(p.read_text())


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
