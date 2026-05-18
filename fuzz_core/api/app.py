from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from ..config import ConfigStore
from ..ipc.uds import UdsRpcServer
from ..offline.instrument import InstrumentationService
from ..offline.protocol import ProtocolSpecService
from ..offline.risk import RiskAnalysisService
from ..offline.seeds import SeedService
from ..runner.manager import JobManager
from ..runner.models import JobCreateRequest
from ..sdk import LocalCoreClient
from ..state import AppState
from .routers import compat, config_router, health, jobs, offline


def build_uds_handlers(state: AppState) -> dict:
    async def _sub(channel: str):
        queue = await state.manager.subscribe(channel)
        return ({'channel': channel}, queue)

    return {
        'system.ping': lambda: {'ok': True},
        'system.info': state.manager.system_info,
        'system.capabilities': state.manager.capabilities,
        'config.get': state.config_store.as_dict,
        'config.patch': lambda patch: state.config_store.update(patch).model_dump(mode='python'),
        'offline.protocol.analyze': lambda **params: state.local_client.analyze_protocol(params),
        'offline.seeds.generate': lambda **params: state.local_client.generate_seeds(params),
        'offline.risk.analyze': lambda **params: state.local_client.analyze_risk(params),
        'offline.risk.preview': lambda **params: state.local_client.preview_risk(params),
        'offline.instrument': lambda **params: state.local_client.instrument_source(params),
        'jobs.create': lambda **params: state.manager.create_job(JobCreateRequest.model_validate(params)).model_dump(mode='json'),
        'jobs.list': lambda: [job.model_dump(mode='json') for job in state.manager.list_jobs()],
        'jobs.get': lambda job_id: state.manager.get_job(job_id).model_dump(mode='json'),
        'jobs.lookup_by_output': lambda output_path: (state.manager.lookup_by_output(output_path).model_dump(mode='json') if state.manager.lookup_by_output(output_path) else None),
        'jobs.lookup_by_pid': lambda pid: (state.manager.lookup_by_pid(int(pid)).model_dump(mode='json') if state.manager.lookup_by_pid(int(pid)) else None),
        'jobs.stop': lambda job_id: state.manager.stop_job(job_id).model_dump(mode='json'),
        'jobs.metrics.get': lambda job_id: (state.manager.get_metrics(job_id).model_dump(mode='json') if state.manager.get_metrics(job_id) else None),
        'jobs.metrics.history': lambda job_id, limit=200: state.manager.get_metrics_history(job_id, limit=limit),
        'jobs.artifacts.list': lambda job_id: [item.model_dump(mode='json') for item in state.manager.list_artifacts(job_id)],
        'jobs.artifacts.get': lambda job_id, artifact_id: state.manager.get_artifact(job_id, artifact_id).model_dump(mode='json'),
        'jobs.artifacts.replay': lambda job_id, artifact_id: state.manager.replay_artifact(job_id, artifact_id).model_dump(mode='json'),
        'jobs.artifacts.analyze': lambda job_id, artifact_id: state.manager.analyze_artifact(job_id, artifact_id).model_dump(mode='json'),
        'jobs.logs.tail': lambda job_id, limit=100: state.manager.get_logs_tail(job_id, limit=limit),
        'jobs.events.subscribe': lambda job_id: _sub(f'events:{job_id}'),
        'jobs.metrics.subscribe': lambda job_id: _sub(f'metrics:{job_id}'),
        'jobs.artifacts.subscribe': lambda job_id: _sub(f'artifacts:{job_id}'),
    }


def create_state(config_path: str | None = None) -> AppState:
    config_store = ConfigStore(config_path)
    manager = JobManager(config_store)
    protocol_service = ProtocolSpecService(config_store)
    seed_service = SeedService(config_store)
    risk_service = RiskAnalysisService(config_store)
    instrument_service = InstrumentationService(config_store, risk_service)
    local_client = LocalCoreClient(config_store, manager, protocol_service, seed_service, risk_service, instrument_service)
    return AppState(
        config_store=config_store,
        manager=manager,
        protocol_service=protocol_service,
        seed_service=seed_service,
        risk_service=risk_service,
        instrument_service=instrument_service,
        local_client=local_client,
    )


def create_app(config_path: str | None = None) -> FastAPI:
    state = create_state(config_path)
    uds_server: UdsRpcServer | None = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal uds_server
        loop = asyncio.get_running_loop()
        state.manager.set_loop(loop)
        if state.config_store.get().server.uds.enabled:
            uds_server = UdsRpcServer(state.config_store.get().server.uds.path, build_uds_handlers(state))
            await uds_server.start()
        yield
        if uds_server is not None:
            await uds_server.close()

    app = FastAPI(title='Fuzz Core', version='0.2.0', lifespan=lifespan)
    
    cors = state.config_store.get().server.cors
    if cors.enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors.allow_origins,
            allow_origin_regex=cors.allow_origin_regex,
            allow_credentials=cors.allow_credentials,
            allow_methods=cors.allow_methods,
            allow_headers=cors.allow_headers,
            expose_headers=cors.expose_headers,
            max_age=cors.max_age,
        )
    
    app.state.core = state
    app.include_router(health.router)
    app.include_router(config_router.router)
    app.include_router(offline.router)
    app.include_router(jobs.router)
    app.include_router(compat.router)
    return app
