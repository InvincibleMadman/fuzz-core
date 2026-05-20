from __future__ import annotations
from fastapi import APIRouter, Request, HTTPException, WebSocket
from ...models import ApiResponse
router=APIRouter()

@router.post("/api/v1/jobs")
def create_job(request: Request, body: dict):
    return ApiResponse(data=request.app.state.core.runner.create_job(body)).model_dump()

@router.get("/api/v1/jobs")
def list_jobs(request: Request):
    return ApiResponse(data={"items":request.app.state.core.runner.list_jobs()}).model_dump()

@router.get("/api/v1/jobs/{job_id}")
def get_job(job_id: str, request: Request):
    job=request.app.state.core.runner.get_job(job_id)
    if not job: raise HTTPException(404, "job not found")
    return ApiResponse(data=job).model_dump()

@router.post("/api/v1/jobs/{job_id}/stop")
def stop_job(job_id: str, request: Request):
    job=request.app.state.core.runner.stop_job(job_id)
    if not job: raise HTTPException(404, "job not found")
    return ApiResponse(data=job).model_dump()

@router.get("/api/v1/jobs/{job_id}/metrics")
def metrics(job_id: str, request: Request):
    return ApiResponse(data=request.app.state.core.runner.metrics(job_id)).model_dump()

@router.get("/api/v1/jobs/{job_id}/metrics/history")
def metrics_history(job_id: str, request: Request):
    return ApiResponse(data=request.app.state.core.runner.metrics_history(job_id)).model_dump()


@router.get("/api/v1/jobs/{job_id}/debug/candidates")
def job_debug_candidates(job_id: str, request: Request):
    job=request.app.state.core.runner.get_job(job_id)
    if not job: raise HTTPException(404, "job not found")
    return ApiResponse(data={"job_id":job_id,"items":request.app.state.core.runner.debug_candidates(job_id)}).model_dump()

@router.get("/api/v1/jobs/{job_id}/artifacts")
def artifacts(job_id: str, request: Request):
    return ApiResponse(data={"items":request.app.state.core.runner.artifacts(job_id)}).model_dump()

@router.get("/api/v1/jobs/{job_id}/artifacts/{artifact_id}")
def artifact(job_id: str, artifact_id: str, request: Request):
    art=request.app.state.core.runner.get_artifact(job_id, artifact_id)
    if not art: raise HTTPException(404, "artifact not found")
    return ApiResponse(data=art).model_dump()

@router.post("/api/v1/jobs/{job_id}/artifacts/{artifact_id}/replay")
def replay(job_id: str, artifact_id: str, request: Request):
    res=request.app.state.core.runner.replay_artifact(job_id, artifact_id)
    if not res: raise HTTPException(404, "artifact not found")
    return ApiResponse(data=res).model_dump()

@router.post("/api/v1/jobs/{job_id}/artifacts/{artifact_id}/analyze")
def analyze(job_id: str, artifact_id: str, request: Request):
    res=request.app.state.core.runner.analyze_artifact(job_id, artifact_id)
    if not res: raise HTTPException(404, "artifact not found")
    return ApiResponse(data=res).model_dump()

@router.get("/api/v1/jobs/{job_id}/logs/tail")
def logs_tail(job_id: str):
    return ApiResponse(data={"job_id":job_id,"lines":[]}).model_dump()

@router.get("/api/v1/jobs/{job_id}/logs/download")
def logs_download(job_id: str):
    return ApiResponse(data={"job_id":job_id,"download_url":None,"message":"No log bundle available in dry-run manager."}).model_dump()

@router.websocket("/api/v1/jobs/{job_id}/events/ws")
async def events_ws(websocket: WebSocket, job_id: str):
    await websocket.accept()
    await websocket.send_json({"type":"hello","job_id":job_id})
    await websocket.close()

@router.websocket("/api/v1/jobs/{job_id}/metrics/ws")
async def metrics_ws(websocket: WebSocket, job_id: str):
    await websocket.accept()
    await websocket.send_json({"type":"metrics","job_id":job_id})
    await websocket.close()

@router.websocket("/api/v1/jobs/{job_id}/artifacts/ws")
async def artifacts_ws(websocket: WebSocket, job_id: str):
    await websocket.accept()
    await websocket.send_json({"type":"artifacts","job_id":job_id})
    await websocket.close()
