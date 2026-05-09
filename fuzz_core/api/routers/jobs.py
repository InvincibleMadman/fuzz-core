
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from ..deps import get_state
from ...models import ApiEnvelope
from ...runner.models import JobCreateRequest
from ...utils.afl import resolve_afl_binary
from ...state import AppState

router = APIRouter(tags=["jobs"])


@router.post("/api/v1/jobs", response_model=ApiEnvelope)
def create_job(req: JobCreateRequest, state: AppState = Depends(get_state)) -> ApiEnvelope:
    cfg = state.config_store.get()
    req.afl.afl_binary = resolve_afl_binary(cfg, req.afl.afl_binary)
    job = state.manager.create_job(req)
    return ApiEnvelope(data=job.model_dump(mode="json"), msg="job created")


@router.get("/api/v1/jobs", response_model=ApiEnvelope)
def list_jobs(state: AppState = Depends(get_state)) -> ApiEnvelope:
    jobs = [job.model_dump(mode="json") for job in state.manager.list_jobs()]
    return ApiEnvelope(data=jobs)


@router.get("/api/v1/jobs/{job_id}", response_model=ApiEnvelope)
def get_job(job_id: str, state: AppState = Depends(get_state)) -> ApiEnvelope:
    try:
        job = state.manager.get_job(job_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return ApiEnvelope(data=job.model_dump(mode="json"))


@router.post("/api/v1/jobs/{job_id}/stop", response_model=ApiEnvelope)
def stop_job(job_id: str, state: AppState = Depends(get_state)) -> ApiEnvelope:
    try:
        job = state.manager.stop_job(job_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return ApiEnvelope(data=job.model_dump(mode="json"), msg="job stopped")


@router.get("/api/v1/jobs/{job_id}/metrics", response_model=ApiEnvelope)
def get_metrics(job_id: str, state: AppState = Depends(get_state)) -> ApiEnvelope:
    metrics = state.manager.get_metrics(job_id)
    return ApiEnvelope(data=metrics.model_dump(mode="json") if metrics else None)


@router.get("/api/v1/jobs/{job_id}/metrics/history", response_model=ApiEnvelope)
def get_metrics_history(job_id: str, limit: int = 200, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.manager.get_metrics_history(job_id, limit=limit))


@router.get("/api/v1/jobs/{job_id}/artifacts", response_model=ApiEnvelope)
def list_artifacts(job_id: str, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=[item.model_dump(mode="json") for item in state.manager.list_artifacts(job_id)])


@router.get("/api/v1/jobs/{job_id}/artifacts/{artifact_id}", response_model=ApiEnvelope)
def get_artifact(job_id: str, artifact_id: str, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.manager.get_artifact(job_id, artifact_id).model_dump(mode="json"))


@router.post("/api/v1/jobs/{job_id}/artifacts/{artifact_id}/replay", response_model=ApiEnvelope)
def replay_artifact(job_id: str, artifact_id: str, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.manager.replay_artifact(job_id, artifact_id).model_dump(mode="json"))


@router.post("/api/v1/jobs/{job_id}/artifacts/{artifact_id}/analyze", response_model=ApiEnvelope)
def analyze_artifact(job_id: str, artifact_id: str, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.manager.analyze_artifact(job_id, artifact_id).model_dump(mode="json"))


@router.get("/api/v1/jobs/{job_id}/logs/tail", response_model=ApiEnvelope)
def tail_logs(job_id: str, limit: int = 100, state: AppState = Depends(get_state)) -> ApiEnvelope:
    return ApiEnvelope(data=state.manager.get_logs_tail(job_id, limit=limit))


@router.get("/api/v1/jobs/{job_id}/logs/download")
def download_logs(job_id: str, state: AppState = Depends(get_state)) -> FileResponse:
    return FileResponse(path=state.manager.get_log_file(job_id), filename=f"{job_id}.log")


async def _stream_channel(websocket: WebSocket, channel: str, state: AppState) -> None:
    await websocket.accept()
    queue = await state.manager.subscribe(channel)
    try:
        while True:
            message = await queue.get()
            if message is None:
                return
            await websocket.send_text(message)
    except WebSocketDisconnect:
        state.manager.unsubscribe(channel, queue)


@router.websocket("/api/v1/jobs/{job_id}/events/ws")
async def events_ws(websocket: WebSocket, job_id: str) -> None:
    state: AppState = websocket.app.state.core
    await _stream_channel(websocket, f"events:{job_id}", state)


@router.websocket("/api/v1/jobs/{job_id}/metrics/ws")
async def metrics_ws(websocket: WebSocket, job_id: str) -> None:
    state: AppState = websocket.app.state.core
    await _stream_channel(websocket, f"metrics:{job_id}", state)


@router.websocket("/api/v1/jobs/{job_id}/artifacts/ws")
async def artifacts_ws(websocket: WebSocket, job_id: str) -> None:
    state: AppState = websocket.app.state.core
    await _stream_channel(websocket, f"artifacts:{job_id}", state)
