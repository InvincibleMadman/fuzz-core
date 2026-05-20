from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import APIRouter, Request, HTTPException

from ...debugger.models import DebugRequest, TargetConfig
from ...models import ApiResponse

router = APIRouter()


def _stable_manual_artifact_id(path: Path) -> str:
    payload = f"manual:{path.resolve(strict=False)}".encode("utf-8")
    return "artifact-" + hashlib.sha256(payload).hexdigest()[:16]


@router.get("/api/v1/debug/candidates")
def debug_candidates(request: Request, job_id: str | None = None):
    """Return crash seed paths discovered from fuzz jobs for UI selection.

    This does not start GDB. It exposes job_id/artifact_id/seed_path/target so the
    frontend can let a user select a seed and explicitly call /debug/sessions.
    """
    return ApiResponse(data={"job_id": job_id, "items": request.app.state.core.runner.debug_candidates(job_id)}).model_dump()


@router.post("/api/v1/debug/sessions")
def create_debug_session(request: Request, body: dict):
    protocol = body.get("protocol") or "legacy-default"
    artifact_path = body.get("artifact_path") or body.get("seed_path")
    if not artifact_path:
        raise HTTPException(status_code=400, detail="artifact_path or seed_path is required")
    p = Path(artifact_path)
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail=f"seed file not found: {artifact_path}")

    target_body = body.get("target") or {}
    target_body.setdefault("protocol", protocol)
    target = TargetConfig.model_validate(target_body)

    req = DebugRequest(
        protocol=protocol,
        artifact_path=str(p),
        artifact_id=body.get("artifact_id") or _stable_manual_artifact_id(p),
        job_id=body.get("job_id"),
        kb_entry_ids=body.get("kb_entry_ids") or [],
        source_doc_ids=body.get("source_doc_ids") or [],
        target=target,
    )
    result = request.app.state.core.debugger.run(req)
    return ApiResponse(data=result).model_dump()


@router.post("/api/v1/debug/sessions/batch")
def create_debug_sessions_batch(request: Request, body: dict):
    protocol = body.get("protocol") or "legacy-default"
    seed_dir = body.get("seed_dir")
    if not seed_dir:
        raise HTTPException(status_code=400, detail="seed_dir is required")
    root = Path(seed_dir)
    if not root.exists() or not root.is_dir():
        raise HTTPException(status_code=404, detail=f"seed_dir not found: {seed_dir}")

    glob_pattern = body.get("glob") or "*"
    recursive = bool(body.get("recursive", False))
    max_cases = int(body.get("max_cases") or 50)
    iterator = root.rglob(glob_pattern) if recursive else root.glob(glob_pattern)
    files = [p for p in sorted(iterator) if p.is_file() and not p.name.startswith(".") and p.stat().st_size > 0][:max_cases]

    target_body = body.get("target") or {}
    target_body.setdefault("protocol", protocol)
    target = TargetConfig.model_validate(target_body)

    items = []
    for p in files:
        req = DebugRequest(
            protocol=protocol,
            artifact_path=str(p),
            artifact_id=_stable_manual_artifact_id(p),
            job_id=body.get("job_id"),
            source_doc_ids=body.get("source_doc_ids") or [],
            kb_entry_ids=body.get("kb_entry_ids") or [],
            target=target,
        )
        items.append(request.app.state.core.debugger.run(req))

    return ApiResponse(data={
        "protocol": request.app.state.core.paths.protocol(protocol),
        "seed_dir": str(root),
        "glob": glob_pattern,
        "recursive": recursive,
        "count": len(items),
        "items": items,
    }).model_dump()


@router.get("/api/v1/debug/sessions/{session_id}")
def get_debug_session(session_id: str, request: Request):
    session = request.app.state.core.debugger.persistence.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="debug session not found")
    return ApiResponse(data=session).model_dump()


@router.get("/api/v1/protocols/{protocol}/debug/sessions")
def list_protocol_debug_sessions(protocol: str, request: Request, coarse_type: str | None = None, limit: int = 50, offset: int = 0):
    proto = request.app.state.core.paths.protocol(protocol)
    items = request.app.state.core.debugger.persistence.list(proto, coarse_type=coarse_type, limit=limit, offset=offset)
    return ApiResponse(data={"protocol": proto, "coarse_type": coarse_type, "limit": limit, "offset": offset, "items": items}).model_dump()
