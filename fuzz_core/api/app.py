from __future__ import annotations
from fastapi import FastAPI
from ..config import load_config
from ..state import CoreState
from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository
from ..services.vuldoc_service import VulDocService
from ..services.distill_service import DistillService
from ..services.kb_service import KBService
from ..services.seed_service import SeedService
from ..services.risk_service import RiskService
from ..services.history_service import HistoryService
from ..debugger.gdb_driver import GDBDriver
from ..debugger.replayer import Replayer
from ..debugger.classifier import VulnerabilityClassifier
from ..debugger.persistence import DebugPersistence
from ..debugger.session_manager import DebugSessionManager
from ..runner.manager import RunnerManager
from ..services.operation_log_service import OperationLogService

def create_app() -> FastAPI:
    cfg=load_config()
    paths=PathResolver(cfg.workspace.root, cfg.workspace.default_protocol)
    repo=Repository(paths.root/"fuzz_core.sqlite3")
    kb=KBService(paths, repo)
    history=HistoryService(paths, repo)
    debugger=DebugSessionManager(
        GDBDriver(cfg.debugger.gdb_path, cfg.debugger.timeout_sec),
        Replayer(cfg.debugger.allow_network_replay),
        VulnerabilityClassifier(),
        DebugPersistence(paths, repo),
        history,
    )
    operations=OperationLogService(paths.root)
    app=FastAPI(title="fuzz-core enhanced", version="0.2.1")
    app.state.core=CoreState(
        config=cfg, paths=paths, repo=repo,
        vuldocs=VulDocService(paths, repo),
        distill=DistillService(paths, repo),
        kb=kb,
        seeds=SeedService(paths, repo, kb),
        risk=RiskService(paths),
        history=history,
        debugger=debugger,
        runner=RunnerManager(paths, debugger),
        operations=operations,
    )
    from .routers import config_router, system, offline, protocols, jobs, debug, operations as operations_router, compat
    app.include_router(config_router.router)
    app.include_router(system.router)
    app.include_router(offline.router)
    app.include_router(protocols.router)
    app.include_router(jobs.router)
    app.include_router(debug.router)
    app.include_router(operations_router.router)
    app.include_router(compat.router)
    return app
