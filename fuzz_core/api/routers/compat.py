from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request, UploadFile, File, Form
from fastapi.responses import FileResponse

from ...models import CompatResponse

router = APIRouter()


def ok(data=None, msg="ok"):
    return CompatResponse(is_success=True, msg=msg, data=data).model_dump()


def err(msg):
    return CompatResponse(is_success=False, msg=msg, data=None).model_dump()


def _op_id(request: Request, body: dict | None = None) -> str | None:
    return (body or {}).get("operation_id") or request.headers.get("x-operation-id")


@router.post("/extract_protocol")
async def extract_protocol(request: Request, body: dict):
    st = request.app.state.core
    proto = body.get("protocol") or body.get("protocol_name") or None
    op = st.operations.start("compat.extract_protocol", st.paths.protocol(proto), _op_id(request, body), {"name": body.get("name", "protocol_spec.json")})
    try:
        st.operations.append(op["operation_id"], "compat_input", "Compat protocol extraction request received")
        content = body.get("spec") or body.get("content") or body.get("result") or "{}"
        rec = st.seeds.save_spec(proto, content, body.get("name", "protocol_spec.json"))
        st.operations.append(op["operation_id"], "saving_spec", "Spec saved into protocol-scoped storage", {"path": rec["path"]})
        st.operations.finish(op["operation_id"], "finished", {"spec_id": rec["spec_id"]})
        return ok({"out": rec["path"], "protocol": rec["protocol"], "spec_id": rec["spec_id"], "operation_id": op["operation_id"]})
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/upload_Vuldoc")
async def upload_vuldoc(request: Request, protocol: str = Form(None), operation_id: str | None = Form(None), file: UploadFile = File(None), files: list[UploadFile] | None = File(None)):
    st = request.app.state.core
    uploads = []
    if file:
        uploads.append(file)
    if files:
        uploads.extend(files)
    if not uploads:
        return err("no file uploaded")
    op = st.operations.start("compat.upload_Vuldoc", st.paths.protocol(protocol), operation_id or request.headers.get("x-operation-id"), {"file_count": len(uploads)})
    try:
        st.operations.append(op["operation_id"], "upload_start", "Compat VulDoc upload started", {"filenames": [f.filename for f in uploads]})
        docs = await st.vuldocs.upload(protocol, uploads, "compat:/upload_Vuldoc", {"operation_id": op["operation_id"]})
        st.operations.finish(op["operation_id"], "finished", {"doc_ids": [d["doc_id"] for d in docs]})
        return ok({"protocol": st.paths.protocol(protocol), "operation_id": op["operation_id"], "documents": docs, "filenames": [d["filename"] for d in docs]})
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/gen_init_seed")
async def gen_init_seed(request: Request, body: dict):
    st = request.app.state.core
    proto = body.get("protocol") or body.get("protocol_name") or None
    op = st.operations.start("compat.gen_init_seed", st.paths.protocol(proto), _op_id(request, body), {"count": body.get("count", 8)})
    try:
        st.operations.append(op["operation_id"], "resolving_context", "Resolving protocol-scoped spec and KB context for seed generation")
        res = st.seeds.generate(proto, body.get("spec_path") or body.get("protocol_spec_path"), body.get("keyword"), int(body.get("count", 8)), body.get("output_dir") or body.get("outputpath"), True)
        st.operations.append(op["operation_id"], "generated", f"Generated seeds with mode {res.get('generation_mode')}", {"output_dir": res.get("output_dir")})
        st.operations.finish(op["operation_id"], "finished", {"generation_mode": res.get("generation_mode")})
        res["operation_id"] = op["operation_id"]
        return ok(res)
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/risk_code_analysis")
async def risk_code_analysis(request: Request, body: dict):
    st = request.app.state.core
    source_path = body.get("source_path") or body.get("path") or body.get("code_path") or "."
    op = st.operations.start("compat.risk_code_analysis", st.paths.protocol(body.get("protocol")), _op_id(request, body), {"source_path": source_path})
    try:
        st.operations.append(op["operation_id"], "scan_start", "Compat risk analysis scanning source files", {"source_path": source_path})
        data = st.risk.analyze(body.get("protocol"), source_path)
        st.operations.append(op["operation_id"], "scan_complete", "Compat risk analysis completed", {"result_path": data.get("path") or data.get("result_path")})
        st.operations.finish(op["operation_id"], "finished", {"result_path": data.get("path") or data.get("result_path")})
        data["operation_id"] = op["operation_id"]
        return ok(data)
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.get("/risk_analysis_preview")
async def risk_analysis_preview(request: Request, protocol: str | None = None, operation_id: str | None = None):
    st = request.app.state.core
    op = st.operations.start("compat.risk_analysis_preview", st.paths.protocol(protocol), operation_id or request.headers.get("x-operation-id"), {})
    try:
        data = st.risk.preview(protocol)
        st.operations.append(op["operation_id"], "preview", "Loaded compat risk preview")
        st.operations.finish(op["operation_id"], "finished", {})
        if isinstance(data, dict):
            data["operation_id"] = op["operation_id"]
        return ok(data)
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/riskres_upload")
async def riskres_upload(request: Request, protocol: str = Form(None), operation_id: str | None = Form(None), file: UploadFile = File(...)):
    st = request.app.state.core
    op = st.operations.start("compat.riskres_upload", st.paths.protocol(protocol), operation_id or request.headers.get("x-operation-id"), {"filename": file.filename})
    try:
        content = await file.read()
        st.operations.append(op["operation_id"], "upload_read", "Compat risk result upload received", {"bytes": len(content)})
        data = st.risk.upload_result(protocol, content, file.filename or "risk.json")
        st.operations.finish(op["operation_id"], "finished", {"path": data.get("path") or data.get("result_path")})
        data["operation_id"] = op["operation_id"]
        return ok(data)
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/risk_code_instrument")
async def risk_code_instrument(request: Request, body: dict):
    st = request.app.state.core
    source_path = body.get("input_path") or body.get("source_path")
    op = st.operations.start("compat.risk_code_instrument", st.paths.protocol(body.get("protocol")), _op_id(request, body), {"source_path": source_path, "output_path": body.get("output_path")})
    try:
        st.operations.append(op["operation_id"], "instrument_start", "Compat instrumentation started", {"source_path": source_path})
        data = st.risk.instrument(body.get("protocol"), source_path, body.get("output_path"))
        st.operations.finish(op["operation_id"], "finished", {"output_path": data.get("output_path")})
        data["operation_id"] = op["operation_id"]
        return ok(data)
    except Exception as e:
        st.operations.fail(op["operation_id"], e)
        raise


@router.post("/fuzztesting")
async def fuzztesting(request: Request, body: dict):
    st = request.app.state.core
    proto = body.get("protocol") or body.get("protocol_name") or None
    target_cmd = body.get("target_cmd") or body.get("cmd") or []
    if isinstance(target_cmd, str):
        target_cmd = target_cmd.split()
    job = st.runner.create_job({
        "protocol": proto or st.paths.default_protocol,
        "cwd": body.get("cwd") or body.get("workdir"),
        "target_cmd": target_cmd,
        "afl_path": body.get("afl_path"),
        "input_dir": body.get("input_dir"),
        "output_dir": body.get("outputpath") or body.get("output_dir"),
        "dry_run": body.get("dry_run", True),
        "debug": body.get("debug") or {},
    })
    return ok({"pid": None, "job_id": job["job_id"], "outputPath": job["output_dir"], "outputpath": job["output_dir"], "dbPath": str(st.paths.root / "fuzz_core.sqlite3"), "status": job["status"]})


@router.post("/stop_fuzztesting")
async def stop_fuzztesting(request: Request, body: dict):
    job_id = body.get("job_id") or body.get("pid")
    if job_id:
        return ok(request.app.state.core.runner.stop_job(str(job_id)))
    return ok({"stopped": False, "reason": "no job_id provided"})


@router.get("/get_fuzz_stats")
async def get_fuzz_stats(request: Request, outputpath: str | None = None, outputPath: str | None = None):
    path = Path(outputpath or outputPath or "")
    stats = {}
    if path.exists():
        for f in path.rglob("fuzzer_stats"):
            for ln in f.read_text(errors="ignore").splitlines():
                if ":" in ln:
                    k, v = [x.strip() for x in ln.split(":", 1)]
                    stats[k] = v
    return ok(stats)


@router.get("/get_branch_coverage_history")
async def get_branch_coverage_history():
    return ok({"history": []})


@router.get("/download_fuzz_log")
async def download_fuzz_log(dbPath: str | None = None):
    if dbPath and Path(dbPath).exists():
        return FileResponse(dbPath, filename=Path(dbPath).name)
    return ok({"download_url": None, "message": "dbPath not found"})
