from __future__ import annotations

from fastapi import APIRouter, Request, UploadFile, File, Form

from ...models import ApiResponse

router = APIRouter()


def _operation_id(request: Request, body: dict | None = None) -> str | None:
    return (body or {}).get("operation_id") or request.headers.get("x-operation-id")


def _start_op(request: Request, kind: str, protocol: str | None, body: dict | None = None, metadata: dict | None = None):
    st = request.app.state.core
    proto = st.paths.protocol(protocol)
    return st.operations.start(kind, proto, _operation_id(request, body), metadata or {})


@router.post("/api/v1/offline/protocol/analyze")
async def protocol_analyze(request: Request, body: dict):
    st = request.app.state.core
    protocol = body.get("protocol")
    op = _start_op(request, "offline.protocol.analyze", protocol, body, {"name": body.get("name", "protocol_spec.json")})
    try:
        st.operations.append(op["operation_id"], "input", "Received protocol analysis request", {"has_spec": bool(body.get("spec") or body.get("content"))})
        content = body.get("spec") or body.get("content") or "{}"
        st.operations.append(op["operation_id"], "saving_spec", "Writing protocol spec into protocol-scoped workspace")
        rec = st.seeds.save_spec(protocol, content, body.get("name", "protocol_spec.json"))
        st.operations.append(op["operation_id"], "completed", "Protocol spec saved", {"spec_id": rec.get("spec_id"), "path": rec.get("path")})
        st.operations.finish(op["operation_id"], "finished", {"spec_id": rec.get("spec_id")})
        rec["operation_id"] = op["operation_id"]
        return ApiResponse(data=rec).model_dump()
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/api/v1/offline/seeds/generate")
async def seeds_generate(request: Request, body: dict):
    st = request.app.state.core
    op = _start_op(request, "offline.seeds.generate", body.get("protocol"), body, {"count": body.get("count", 8)})
    try:
        st.operations.append(op["operation_id"], "resolving_context", "Resolving latest spec and protocol-scoped KB context")
        data = st.seeds.generate(
            body.get("protocol"),
            body.get("spec_path"),
            body.get("keyword"),
            int(body.get("count", 8)),
            body.get("output_dir"),
            body.get("allow_fallback", True),
        )
        st.operations.append(op["operation_id"], "generation_mode", f"Seed generation mode: {data.get('generation_mode')}", {
            "used_spec_id": data.get("used_spec_id"),
            "used_kb_entry_ids": data.get("used_kb_entry_ids"),
            "warnings": data.get("warnings"),
        })
        st.operations.finish(op["operation_id"], "finished", {"generation_mode": data.get("generation_mode"), "output_dir": data.get("output_dir")})
        data["operation_id"] = op["operation_id"]
        return ApiResponse(data=data).model_dump()
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/api/v1/offline/risk/analyze")
async def risk_analyze(request: Request, body: dict):
    st = request.app.state.core
    source_path = body.get("source_path") or body.get("path") or "."
    op = _start_op(request, "offline.risk.analyze", body.get("protocol"), body, {"source_path": source_path})
    try:
        st.operations.append(op["operation_id"], "scan_start", "Scanning source tree for risk-sensitive files", {"source_path": source_path})
        data = st.risk.analyze(body.get("protocol"), source_path)
        st.operations.append(op["operation_id"], "scan_complete", "Risk path analysis completed", {"result_path": data.get("path") or data.get("result_path"), "items": len(data.get("items", data.get("findings", [])))})
        st.operations.finish(op["operation_id"], "finished", {"result_path": data.get("path") or data.get("result_path")})
        data["operation_id"] = op["operation_id"]
        return ApiResponse(data=data).model_dump()
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/api/v1/offline/risk/preview")
async def risk_preview(request: Request, body: dict | None = None):
    body = body or {}
    st = request.app.state.core
    op = _start_op(request, "offline.risk.preview", body.get("protocol"), body)
    try:
        st.operations.append(op["operation_id"], "preview", "Loading latest protocol-scoped risk analysis preview")
        data = st.risk.preview(body.get("protocol"))
        st.operations.finish(op["operation_id"], "finished", {"items": len(data.get("items", data.get("findings", []))) if isinstance(data, dict) else 0})
        if isinstance(data, dict):
            data["operation_id"] = op["operation_id"]
        return ApiResponse(data=data).model_dump()
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/api/v1/offline/risk/upload")
async def risk_upload(request: Request, protocol: str = Form("legacy-default"), operation_id: str | None = Form(None), file: UploadFile = File(...)):
    st = request.app.state.core
    op = st.operations.start("offline.risk.upload", st.paths.protocol(protocol), operation_id or request.headers.get("x-operation-id"), {"filename": file.filename})
    try:
        content = await file.read()
        st.operations.append(op["operation_id"], "upload_read", "Received risk result upload", {"bytes": len(content)})
        data = st.risk.upload_result(protocol, content, file.filename or "risk.json")
        st.operations.finish(op["operation_id"], "finished", {"path": data.get("path") or data.get("result_path")})
        data["operation_id"] = op["operation_id"]
        return ApiResponse(data=data).model_dump()
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/api/v1/offline/instrument")
async def instrument(request: Request, body: dict):
    st = request.app.state.core
    source_path = body.get("input_path") or body.get("source_path")
    op = _start_op(request, "offline.instrument", body.get("protocol"), body, {"source_path": source_path, "output_path": body.get("output_path")})
    try:
        st.operations.append(op["operation_id"], "instrument_start", "Preparing risk instrumentation", {"source_path": source_path})
        data = st.risk.instrument(body.get("protocol"), source_path, body.get("output_path"))
        st.operations.append(op["operation_id"], "instrument_complete", "Risk instrumentation completed", {"output_path": data.get("output_path")})
        st.operations.finish(op["operation_id"], "finished", {"output_path": data.get("output_path")})
        data["operation_id"] = op["operation_id"]
        return ApiResponse(data=data).model_dump()
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise
