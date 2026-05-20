from __future__ import annotations

import asyncio
from fastapi import APIRouter, Request, HTTPException, WebSocket

from ...models import ApiResponse

router = APIRouter()


@router.get("/api/v1/operations")
def list_operations(request: Request, kind: str | None = None, protocol: str | None = None, status: str | None = None, limit: int = 50, offset: int = 0):
    return ApiResponse(data={"items": request.app.state.core.operations.list(kind, protocol, status, limit, offset)}).model_dump()


@router.get("/api/v1/operations/{operation_id}")
def get_operation(operation_id: str, request: Request):
    op = request.app.state.core.operations.get(operation_id)
    if not op:
        raise HTTPException(404, "operation not found")
    return ApiResponse(data=op).model_dump()


@router.get("/api/v1/operations/{operation_id}/logs/tail")
def tail_operation_logs(operation_id: str, request: Request, since: int = 0, limit: int = 200):
    return ApiResponse(data=request.app.state.core.operations.tail(operation_id, since, limit)).model_dump()


@router.websocket("/api/v1/operations/{operation_id}/logs/ws")
async def operation_logs_ws(websocket: WebSocket, operation_id: str):
    await websocket.accept()
    service = websocket.app.state.core.operations
    since = 0
    try:
        while True:
            payload = service.tail(operation_id, since=since, limit=100)
            since = payload.get("next_seq", since)
            await websocket.send_json({"type": "operation_logs", "data": payload})
            if payload.get("status") in {"finished", "failed"}:
                break
            await asyncio.sleep(1.0)
    finally:
        await websocket.close()
