
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..deps import get_state
from ...state import AppState

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@router.get("/api/v1/system/info")
def system_info(state: AppState = Depends(get_state)) -> dict:
    return state.manager.system_info()


@router.get("/api/v1/system/capabilities")
def system_capabilities(state: AppState = Depends(get_state)) -> dict:
    return state.manager.capabilities()
