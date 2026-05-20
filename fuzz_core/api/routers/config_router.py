from fastapi import APIRouter, Request
from ...models import ApiResponse
from ...config import AppConfig
router=APIRouter()

@router.get("/api/v1/config")
def get_config(request: Request):
    return ApiResponse(data=request.app.state.core.config.model_dump()).model_dump()

@router.patch("/api/v1/config")
def patch_config(request: Request, patch: dict):
    cfg=request.app.state.core.config.model_dump()
    def merge(a,b):
        for k,v in b.items():
            if isinstance(v,dict) and isinstance(a.get(k),dict): merge(a[k],v)
            else: a[k]=v
    merge(cfg, patch)
    request.app.state.core.config=AppConfig.model_validate(cfg)
    return ApiResponse(data=request.app.state.core.config.model_dump()).model_dump()
