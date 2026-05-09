from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse

from ..deps import get_state
from ...runner.models import AFLConfigModel, AnalysisPolicyModel, DebugConfigModel, JobCreateRequest, ReplayConfigModel
from ...state import AppState
from ...utils.afl import resolve_afl_binary, runtime_dirs
from ...utils.fs import extract_numeric_value, guess_stats_file, parse_fuzzer_stats, read_history_db
from ...backend_rewrite.jsonresp.jsonresponse import JsonResp

router = APIRouter(tags=['compat'])
JP = JsonResp()


async def _payload(request: Request) -> dict[str, Any]:
    ctype = (request.headers.get('content-type') or '').lower()
    if 'application/json' in ctype:
        return await request.json()
    if 'multipart/form-data' in ctype or 'application/x-www-form-urlencoded' in ctype:
        form = await request.form()
        data: dict[str, Any] = {}
        for key, value in form.multi_items():
            if hasattr(value, 'filename'):
                data.setdefault(key, []).append(value)
            else:
                data[key] = value
        return data
    return {}


def _branch_coverage_value(stats_dict: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ('t_bits(branch)', 't_bits', 't_bits(branches)', 'bitmap_cvg'):
        if key in stats_dict:
            value = extract_numeric_value(stats_dict.get(key))
            if value is not None:
                return value, key
    return None, None


@router.post('/extract_protocol')
async def extract_protocol(request: Request, state: AppState = Depends(get_state)):
    data = await _payload(request)
    src = data.get('src') or data.get('sourcePath') or data.get('source_path')
    out = data.get('out') or data.get('outputPath') or data.get('output_path')
    protocol = data.get('protocol') or data.get('protocolName') or data.get('protocol_name')
    if not src or not out or not protocol:
        return JP.get_error(msg='Missing required parameter: src/out/protocol')
    result = state.protocol_service.analyze_source(
        src,
        out,
        protocol,
        bool(data.get('copyToScanDir') or False),
        lang=data.get('lang', 'c'),
        implementation=data.get('implementation', ''),
        protocol_style=data.get('protocol_style', data.get('protocolStyle', 'auto')),
        profile=data.get('profile', 'auto'),
        protocol_variant=data.get('protocol_variant', data.get('protocolVariant', '')),
        iterations=data.get('iterations'),
        temperature=data.get('temperature'),
        max_tokens=data.get('max_tokens', data.get('maxTokens')),
    )
    return JP.get_success(data=result['protocol'])


@router.post('/upload_Vuldoc')
async def upload_vuldoc(request: Request, state: AppState = Depends(get_state)):
    form = await request.form()
    files = form.getlist('file')
    if not files:
        return JP.get_error(msg='Vuldoc is empty')
    cfg = state.config_store.get()
    target_dir = Path(cfg.legacy_paths.vuldoc_upload_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    uploaded: list[str] = []
    for item in files:
        if not isinstance(item, UploadFile):
            continue
        name = item.filename or 'upload.bin'
        payload = await item.read()
        (target_dir / name).write_bytes(payload)
        uploaded.append(name)
    if not uploaded:
        return JP.get_error(msg='Upload Vuldoc failed')
    return JP.get_success(data=uploaded)


@router.post('/gen_init_seed')
async def gen_init_seed(request: Request, state: AppState = Depends(get_state)):
    data = await _payload(request)
    count = int(data.get('count') or data.get('vectorCount') or state.config_store.get().offline.default_seed_count)
    binary = str(data.get('binary', 'true')).lower() not in {'0', 'false', 'no', 'off'}
    result = state.seed_service.generate(
        spec_path=data.get('specPath') or data.get('spec_path'),
        spec_dir=data.get('specDir') or data.get('spec_dir'),
        output_dir=data.get('outputDir') or data.get('output_dir'),
        count=count,
        binary=binary,
        issue_doc_dir=data.get('issueDocDir') or data.get('issue_doc_dir'),
        use_uploaded_vuldocs=True,
    )
    return JP.get_success(data=result['bin_hex'] if result['bin_hex'] else result)


@router.post('/risk_code_analysis')
async def risk_code_analysis(request: Request, state: AppState = Depends(get_state)):
    data = await _payload(request)
    target = data.get('targetPath') or data.get('sourcePath') or data.get('source_path')
    if not target:
        return JP.get_error(msg='targetPath must be provided')
    output = data.get('outputPath') or data.get('output_path')
    result = state.risk_service.analyze(
        target,
        output,
        bool(data.get('copyToScanDir') or False),
        iterations=data.get('iterations'),
        temperature_coefficient=data.get('temperatureCoefficient'),
        max_tokens=data.get('maxTokens'),
    )
    return JP.get_success(data=result['analysis'])


@router.get('/risk_analysis_preview')
async def risk_analysis_preview(analysisPath: str | None = Query(None), state: AppState = Depends(get_state)):
    return JP.get_success(data=state.risk_service.preview(analysisPath))


@router.post('/riskres_upload')
async def riskres_upload(request: Request, state: AppState = Depends(get_state)):
    form = await request.form()
    files = form.getlist('file')
    if not files:
        return JP.get_error(msg='Riskdoc is empty')
    saved = []
    for item in files:
        if not isinstance(item, UploadFile):
            continue
        payload = await item.read()
        saved.append(state.instrument_service.save_uploaded_analysis(item.filename or 'final_analysis.json', payload))
    if not saved:
        return JP.get_error(msg='Upload Riskdoc failed')
    return JP.get_success(data=saved)


@router.post('/risk_code_instrument')
async def risk_code_instrument(request: Request, state: AppState = Depends(get_state)):
    data = await _payload(request)
    try:
        result = state.instrument_service.instrument(
            source_path=data.get('targetPath') or data.get('sourcePath') or data.get('source_path'),
            analysis_path=data.get('analysisPath') or data.get('analysis_path'),
            output_path=data.get('outputPath') or data.get('output_path'),
            in_place=bool(data.get('inPlace') or False),
        )
        return JP.get_success(data=result)
    except Exception as exc:
        return JP.get_error(msg=f'risk code instrument failed: {exc}')


@router.post('/fuzztesting')
async def fuzztesting(request: Request, state: AppState = Depends(get_state)):
    data = await _payload(request)
    seed_path = str(data.get('seedPath', '')).strip()
    output_path = str(data.get('outputPath', '')).strip()
    target_path = str(data.get('targetPath', '')).strip()
    if not seed_path:
        return JP.get_error(msg='seedPath must be provided')
    if not output_path:
        return JP.get_error(msg='outputPath must be provided')
    if not target_path:
        return JP.get_error(msg='targetPath must be provided')

    cfg = state.config_store.get()
    fuzzer_args = ['-m', cfg.runtime.afl_default_memory]
    risk_aware = str(data.get('riskAware', 'true')).strip().lower() in {'true', '1', 'yes', 'on'}
    if risk_aware:
        fuzzer_args.append('-P')
    dirs = runtime_dirs(data)
    afl = AFLConfigModel(
        afl_binary=resolve_afl_binary(cfg, data.get('aflBinary')),
        target_binary=target_path,
        input_dir=seed_path,
        output_dir=output_path,
        run_cwd=dirs['run_cwd'],
        source_dir=dirs['source_dir'],
        build_dir=dirs['build_dir'],
        target_args=data.get('targetArgs') or [],
        fuzzer_args=fuzzer_args + list(data.get('aflArgs') or []),
        env=dict(cfg.afl.default_env),
        workers=int(data.get('workers') or cfg.afl.default_workers),
    )
    if cfg.runtime.use_preeny_desock and Path(cfg.runtime.preeny_desock_path).exists():
        afl.env['LD_PRELOAD'] = cfg.runtime.preeny_desock_path

    job = state.manager.create_job(
        JobCreateRequest(
            name=data.get('jobName') or data.get('name'),
            afl=afl,
            replay=ReplayConfigModel(enabled=True, timeout_sec=cfg.afl.replay_timeout_sec),
            debug=DebugConfigModel(enabled=bool(data.get('debugEnabled') or False)),
            analysis_policy=AnalysisPolicyModel(enabled=bool(data.get('analysisEnabled') if data.get('analysisEnabled') is not None else True)),
            metadata=data,
        )
    )
    return JP.get_success(
        data={
            'jobId': job.job_id,
            'pid': job.pids[0] if job.pids else None,
            'outputPath': job.output_dir,
            'statsFilePath': job.stats_file_path,
            'dbPath': job.db_path,
            'logPath': job.log_path,
            'job': job.model_dump(mode='json'),
        }
    )


@router.post('/stop_fuzztesting')
async def stop_fuzztesting(request: Request, state: AppState = Depends(get_state)):
    data = await _payload(request)
    pid = data.get('pid')
    job_id = data.get('jobId')
    output_path = data.get('outputPath') or data.get('outputpath')
    job = None
    if job_id:
        job = state.manager.stop_job(str(job_id))
    elif pid:
        found = state.manager.lookup_by_pid(int(pid))
        if not found:
            return JP.get_error(msg='PID not found')
        job = state.manager.stop_job(found.job_id)
    elif output_path:
        found = state.manager.lookup_by_output(str(output_path))
        if not found:
            return JP.get_error(msg='job not found for output path')
        job = state.manager.stop_job(found.job_id)
    else:
        return JP.get_error(msg='PID must be provided')
    return JP.get_success(data={'jobId': job.job_id, 'status': job.status, 'pids': job.pids})


@router.get('/get_fuzz_stats')
async def get_fuzz_stats(outputPath: str | None = Query(None), outputpath: str | None = Query(None), state: AppState = Depends(get_state)):
    raw = str(outputPath or outputpath or '').strip()
    if not raw:
        return JP.get_error(msg='outputPath must be provided')
    path = Path(raw).expanduser().resolve()
    stats_file = guess_stats_file(path)
    if stats_file is None:
        found = state.manager.lookup_by_output(str(path))
        if found and found.last_metrics:
            metrics = found.last_metrics.model_dump(mode='json')
            coverage_value, coverage_key = _branch_coverage_value(metrics.get('raw', {}))
            metrics['coverageMetric'] = coverage_key
            metrics['branchCoverage'] = coverage_value
            metrics['status'] = 'ok'
            return JP.get_success(data=metrics)
        return JP.get_error(msg=f'outputPath does not exist: {path}')
    stats = parse_fuzzer_stats(stats_file)
    coverage_value, coverage_key = _branch_coverage_value(stats)
    payload = dict(stats)
    payload.update({'coverageMetric': coverage_key, 'branchCoverage': coverage_value, 'status': 'ok'})
    return JP.get_success(data=payload)


@router.get('/get_branch_coverage_history')
async def get_branch_coverage_history(outputPath: str | None = Query(None), outputpath: str | None = Query(None), state: AppState = Depends(get_state)):
    raw = str(outputPath or outputpath or '').strip()
    if not raw:
        return JP.get_error(msg='outputPath must be provided')
    path = Path(raw).expanduser().resolve()
    found = state.manager.lookup_by_output(str(path))
    db_candidates = []
    if found and found.db_path:
        db_candidates.append(Path(found.db_path))
    db_candidates.append(path / 'fuzzing_result.db')
    db_candidates.append(path / 'default' / 'fuzz_bitmap.db')
    db_path = next((item for item in db_candidates if item.exists()), None)
    if db_path is None:
        return JP.get_success(data=[])
    return JP.get_success(data=read_history_db(db_path, limit=1000))


@router.get('/download_fuzz_log')
async def download_fuzz_log(jobId: str | None = Query(None), dbPath: str | None = Query(None), state: AppState = Depends(get_state)):
    if jobId:
        return FileResponse(state.manager.get_log_file(jobId), filename=f'{jobId}.log')
    if dbPath:
        path = Path(dbPath).expanduser().resolve()
        if not path.exists():
            raise HTTPException(404, 'db path not found')
        return FileResponse(path, filename=path.name)
    raise HTTPException(400, 'jobId or dbPath is required')
