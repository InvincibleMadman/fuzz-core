
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..deps import get_state
from ...models import ApiEnvelope, ConfigPatchRequest
from ...state import AppState
from ...utils.afl import resolve_afl_tools

router = APIRouter(tags=["config"])


@router.get("/api/v1/config", response_model=ApiEnvelope)
def get_config(state: AppState = Depends(get_state)) -> ApiEnvelope:
    cfg = state.config_store.get()
    payload = state.config_store.as_dict()
    payload.setdefault('runtime_info', {})['resolved_afl_tools'] = resolve_afl_tools(cfg)
    return ApiEnvelope(data=payload)


@router.patch("/api/v1/config", response_model=ApiEnvelope)
def patch_config(req: ConfigPatchRequest, state: AppState = Depends(get_state)) -> ApiEnvelope:
    cfg = state.config_store.update(req.patch)
    return ApiEnvelope(data=cfg.model_dump(mode="python"), msg="config updated")
