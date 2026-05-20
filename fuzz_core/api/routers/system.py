from fastapi import APIRouter
from ...models import ApiResponse
router=APIRouter()

@router.get("/api/v1/system/info")
def info():
    return ApiResponse(data={"name":"fuzz-core","version":"0.2.0","api_compatibility":"preserved"}).model_dump()

@router.get("/api/v1/system/capabilities")
def capabilities():
    return ApiResponse(data={
        "protocol_scoped_storage": True,
        "vuldoc_upload": True,
        "document_distillation": True,
        "knowledge_base": True,
        "kb_visualization": ["summary","graph","timeline"],
        "debugger": ["gdb","stdin","udp","tcp","file","custom"],
        "legacy_compat": True,
    }).model_dump()
