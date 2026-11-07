"""
IoC Sentinel API (Day 1): submit a URL, get sandbox observations + containment log.
Day 2 adds the agent loop (Vultr Serverless Inference + host-side threat-intel tools).

  uvicorn app.main:app --app-dir apps/api --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from .agent.loop import investigate
from .config import settings
from .ratelimit import enforce
from .sandbox.runner import run_in_sandbox, save_artifacts
from .sandbox.url_guard import UnsafeTarget, normalize_target

app = FastAPI(title="IoC Sentinel", version="0.2.0")
WEB_DIR = Path(__file__).resolve().parents[3] / "web"  # static front end (also deployable on its own, e.g. Cloudflare Pages)

# The front end may live on another origin (Cloudflare Pages). Only the origins listed in CORS_ORIGINS may call the API
# from a browser; empty = same-origin only. No cookies/credentials are used, so allow_credentials stays False.
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        expose_headers=["Retry-After"],
        max_age=600,
    )
SCANS = settings.data_dir / "scans"
INVESTIGATIONS = settings.data_dir / "investigations"
_SLOTS = asyncio.Semaphore(2)  # max concurrent agent investigations
JOBS: dict[str, dict] = {}     # in-memory state of async investigations (finished ones are also on disk)
_MAX_JOBS = 200


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
    return FileResponse(WEB_DIR / "index.html", media_type="text/html")


@app.get("/config.js", include_in_schema=False)
def front_config():
    return FileResponse(WEB_DIR / "config.js", media_type="text/javascript")


@app.get("/healthz")
def healthz():
    return {"ok": True, "sandbox_image": settings.sandbox_image,
            "runtime": settings.sandbox_runtime or "runc", "network": settings.sandbox_network}


@app.post("/api/scans")
async def create_scan(req: ScanRequest, request: Request):
    try:
        target = normalize_target(req.url)
    except UnsafeTarget as exc:
        raise HTTPException(400, str(exc))
    enforce(request)
    run = await run_in_threadpool(run_in_sandbox, target)
    save_artifacts(run)
    return json.loads((SCANS / run.scan_id / "result.json").read_text())


@app.post("/api/investigations")
async def create_investigation(req: ScanRequest, request: Request, wait: bool = True, lang: str = "en"):
    """Full agent run: LLM (Vultr Serverless Inference) + sandboxed scan + host-side threat intel.

    wait=true (default): block and return the finished result.
    wait=false: return {investigation_id, status:"running"} at once; poll GET /api/investigations/{id}.
    lang=en|es: language of the agent's own summary/findings (the rest of the report is bilingual).
    """
    try:
        target = normalize_target(req.url)
    except UnsafeTarget as exc:
        raise HTTPException(400, str(exc))
    enforce(request)  # per-IP quota (429 + Retry-After)
    # Public demo: cap concurrent runs (each = 1 sandbox container + LLM spend).
    if _SLOTS.locked():
        raise HTTPException(429, "Too many investigations running; retry in a few seconds.")
    inv_id = uuid.uuid4().hex[:12]

    if wait:  # blocking mode (curl / scripts): returns the finished result
        async with _SLOTS:
            try:
                result = await run_in_threadpool(investigate, target, None, lang)
            except RuntimeError as exc:  # e.g. inference key not configured
                raise HTTPException(503, str(exc))
        return _persist(inv_id, result)

    # Async mode (dashboard): return immediately, the client polls GET /api/investigations/{id}
    # and renders the agent events as they happen.
    job = {"status": "running", "url": target, "events": [], "started": time.time()}
    JOBS[inv_id] = job
    for old in list(JOBS)[:-_MAX_JOBS]:  # bound memory
        JOBS.pop(old, None)

    async def runner() -> None:
        async with _SLOTS:
            try:
                result = await run_in_threadpool(investigate, target, job["events"].append, lang)
                job["result"] = _persist(inv_id, result)
                job["status"] = "done"
            except Exception as exc:  # surface any failure to the polling client
                job["status"] = "error"
                job["error"] = f"{exc.__class__.__name__}: {str(exc)[:300]}"

    asyncio.create_task(runner())
    return {"investigation_id": inv_id, "status": "running"}


def _persist(inv_id: str, result: dict) -> dict:
    result["investigation_id"] = inv_id
    d = INVESTIGATIONS / inv_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "investigation.json").write_text(json.dumps(result, indent=2, default=str))
    return result


@app.get("/api/investigations/{inv_id}")
def get_investigation(inv_id: str):
    if not inv_id.isalnum():
        raise HTTPException(400, "bad investigation id")
    job = JOBS.get(inv_id)
    if job and job["status"] == "running":
        return {"investigation_id": inv_id, "status": "running", "url": job["url"],
                "elapsed_s": round(time.time() - job["started"], 1), "events": list(job["events"])}
    if job and job["status"] == "error":
        return {"investigation_id": inv_id, "status": "error", "error": job["error"]}
    p = INVESTIGATIONS / inv_id / "investigation.json"
    if not p.exists():
        raise HTTPException(404, "investigation not found")
    return {"status": "done", **json.loads(p.read_text())}


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
