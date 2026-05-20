from __future__ import annotations

from fastapi import APIRouter, Request, UploadFile, File, Query, HTTPException, Form

from ...models import ApiResponse
from ...services.protocol_service import ProtocolService

router = APIRouter()


def svc(request: Request):
    st = request.app.state.core
    return ProtocolService(st.paths, st.repo, st.kb)


def _op_id(request: Request, body: dict | None = None) -> str | None:
    return (body or {}).get("operation_id") or request.headers.get("x-operation-id")


@router.get("/api/v1/protocols")
def protocols(request: Request):
    return ApiResponse(data={"protocols": svc(request).list_protocols()}).model_dump()


@router.get("/api/v1/protocols/{protocol}/summary")
def protocol_summary(protocol: str, request: Request):
    return ApiResponse(data=svc(request).summary(protocol)).model_dump()


@router.post("/api/v1/protocols/{protocol}/vuldocs/upload")
async def vuldocs_upload(protocol: str, request: Request, operation_id: str | None = Form(None), files: list[UploadFile] = File(...)):
    st = request.app.state.core
    proto = st.paths.protocol(protocol)
    op = st.operations.start("protocol.vuldocs.upload", proto, operation_id or request.headers.get("x-operation-id"), {"file_count": len(files)})
    try:
        st.operations.append(op["operation_id"], "upload_start", "Saving VulDoc files into protocol-scoped raw storage", {"filenames": [f.filename for f in files]})
        docs = await st.vuldocs.upload(protocol, files, "api", {"operation_id": op["operation_id"]})
        st.operations.append(op["operation_id"], "upload_complete", "VulDoc upload completed", {"doc_ids": [d["doc_id"] for d in docs]})
        st.operations.finish(op["operation_id"], "finished", {"doc_ids": [d["doc_id"] for d in docs]})
        return ApiResponse(data={"protocol": proto, "operation_id": op["operation_id"], "documents": docs}).model_dump()
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/api/v1/protocols/{protocol}/vuldocs/distill")
async def vuldocs_distill(protocol: str, request: Request, body: dict | None = None):
    body = body or {}
    st = request.app.state.core
    proto = st.paths.protocol(protocol)
    op = st.operations.start("protocol.vuldocs.distill", proto, _op_id(request, body), {"doc_ids": body.get("doc_ids")})
    try:
        st.operations.append(op["operation_id"], "distill_start", "Extracting structured vulnerability facts from protocol-scoped documents")
        entries = st.distill.distill_protocol(protocol, body.get("doc_ids"))
        st.operations.append(op["operation_id"], "kb_update", "Distilled entries written into local KB", {"entry_ids": [e["entry_id"] for e in entries]})
        st.operations.finish(op["operation_id"], "finished", {"entry_count": len(entries)})
        return ApiResponse(data={"protocol": proto, "operation_id": op["operation_id"], "entries": entries}).model_dump()
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.get("/api/v1/protocols/{protocol}/vuldocs")
def vuldocs_list(protocol: str, request: Request, limit: int = 100, offset: int = 0):
    st = request.app.state.core
    return ApiResponse(data={"protocol": st.paths.protocol(protocol), "items": st.vuldocs.list(protocol, limit, offset)}).model_dump()


@router.get("/api/v1/protocols/{protocol}/vuldocs/{doc_id}")
def vuldoc_get(protocol: str, doc_id: str, request: Request):
    doc = request.app.state.core.vuldocs.get(doc_id)
    if not doc or doc["protocol"] != request.app.state.core.paths.protocol(protocol):
        raise HTTPException(404, "document not found in protocol scope")
    return ApiResponse(data=doc).model_dump()


@router.get("/api/v1/protocols/{protocol}/kb/summary")
def kb_summary(protocol: str, request: Request):
    return ApiResponse(data=request.app.state.core.kb.summary(protocol)).model_dump()


@router.get("/api/v1/protocols/{protocol}/kb/search")
def kb_search(protocol: str, request: Request, coarse_type: str | None = None, vuln_type: str | None = None, cwe: str | None = None, keyword: str | None = None, limit: int = 50, offset: int = 0):
    st = request.app.state.core
    return ApiResponse(data={"protocol": st.paths.protocol(protocol), "items": st.kb.search(protocol, coarse_type, vuln_type, cwe, keyword, limit, offset)}).model_dump()


@router.get("/api/v1/protocols/{protocol}/kb/vulns")
def kb_vulns(protocol: str, request: Request, coarse_type: str | None = None, vuln_type: str | None = None, cwe: str | None = None, keyword: str | None = None, limit: int = 100, offset: int = 0):
    st = request.app.state.core
    return ApiResponse(data={"protocol": st.paths.protocol(protocol), "items": st.kb.search(protocol, coarse_type, vuln_type, cwe, keyword, limit, offset)}).model_dump()


@router.get("/api/v1/protocols/{protocol}/kb/vulns/{vuln_id}")
def kb_vuln_get(protocol: str, vuln_id: str, request: Request):
    item = request.app.state.core.kb.get(vuln_id)
    if not item or item["protocol"] != request.app.state.core.paths.protocol(protocol):
        raise HTTPException(404, "KB entry not found in protocol scope")
    return ApiResponse(data=item).model_dump()


@router.get("/api/v1/protocols/{protocol}/kb/graph")
def kb_graph(protocol: str, request: Request):
    return ApiResponse(data=request.app.state.core.kb.graph(protocol)).model_dump()


@router.get("/api/v1/protocols/{protocol}/kb/timeline")
def kb_timeline(protocol: str, request: Request):
    return ApiResponse(data=request.app.state.core.kb.timeline(protocol)).model_dump()


@router.get("/api/v1/protocols/{protocol}/vulns/history")
def vuln_history(protocol: str, request: Request, coarse_type: str | None = None, limit: int = 100, offset: int = 0):
    st = request.app.state.core
    return ApiResponse(data={"protocol": st.paths.protocol(protocol), "items": st.history.list(protocol, coarse_type, limit, offset)}).model_dump()


@router.get("/api/v1/protocols/{protocol}/vulns/history/{record_id}")
def vuln_history_get(protocol: str, record_id: str, request: Request):
    rec = request.app.state.core.history.get(record_id)
    if not rec or rec["protocol"] != request.app.state.core.paths.protocol(protocol):
        raise HTTPException(404, "history record not found in protocol scope")
    return ApiResponse(data=rec).model_dump()
