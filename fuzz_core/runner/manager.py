from __future__ import annotations

import asyncio
import json
import threading
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..config import ConfigStore
from ..utils.afl import resolve_afl_tools
from ..utils.fs import append_history_db, guess_stats_file, init_history_db, parse_fuzzer_stats, read_history_db, tail_lines, utc_now_iso
from .engine import ExecEngine
from .models import AnalysisResult, ArtifactKind, ArtifactRecord, EventMessage, Job, JobCreateRequest, JobStatus, Metrics, ReplayStatus
from .storage import JobStorage


def _to_int(raw: str | None) -> int:
    try:
        return int(float(raw or 0))
    except (TypeError, ValueError):
        return 0


def _to_float(raw: str | None) -> float:
    if raw is None:
        return 0.0
    try:
        return float(str(raw).strip('%'))
    except (TypeError, ValueError):
        return 0.0


class JobRuntime:
    def __init__(self, job: Job, storage: JobStorage, engine: ExecEngine) -> None:
        self.job = job
        self.storage = storage
        self.engine = engine
        self.stop_event = threading.Event()
        self.metrics_thread: threading.Thread | None = None
        self.artifact_thread: threading.Thread | None = None
        self.known_artifacts: dict[str, ArtifactRecord] = {}


class JobManager:
    def __init__(self, config_store: ConfigStore) -> None:
        self.config_store = config_store
        self._jobs: dict[str, JobRuntime] = {}
        self._jobs_by_output: dict[str, str] = {}
        self._lock = threading.RLock()
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def _jobs_root(self) -> Path:
        return Path(self.config_store.get().paths.jobs_dir).resolve()

    def _emit(self, channel: str, payload: dict[str, Any]) -> None:
        if self._loop is None:
            return
        message = json.dumps(payload, ensure_ascii=False)
        for queue in list(self._subscribers.get(channel, [])):
            self._loop.call_soon_threadsafe(queue.put_nowait, message)

    async def subscribe(self, channel: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers[channel].append(queue)
        return queue

    def unsubscribe(self, channel: str, queue: asyncio.Queue) -> None:
        if queue in self._subscribers.get(channel, []):
            self._subscribers[channel].remove(queue)

    def create_job(self, request: JobCreateRequest) -> Job:
        with self._lock:
            job_id = uuid.uuid4().hex[:12]
            now = utc_now_iso()
            storage = JobStorage(self._jobs_root() / job_id)
            init_history_db(storage.db_file)
            engine = ExecEngine(request.afl, storage.log_file)
            job = Job(
                job_id=job_id,
                name=request.name or job_id,
                status=JobStatus.starting,
                created_at=now,
                updated_at=now,
                afl=request.afl,
                replay=request.replay,
                debug=request.debug,
                analysis_policy=request.analysis_policy,
                metadata=request.metadata,
                output_dir=request.afl.output_dir,
                log_path=str(storage.log_file),
                db_path=str(storage.db_file),
            )
            runtime = JobRuntime(job=job, storage=storage, engine=engine)
            self._jobs[job_id] = runtime
            self._jobs_by_output[str(Path(request.afl.output_dir).resolve())] = job_id

            try:
                pids = engine.start()
                job.pids = pids
                job.status = JobStatus.running
                stats_file = guess_stats_file(Path(request.afl.output_dir).resolve())
                if stats_file:
                    job.stats_file_path = str(stats_file)
                job.updated_at = utc_now_iso()
                storage.save_job(job)
                self._start_watchers(runtime)
                self._emit_event(job_id, 'job.started', {'pids': pids})
                return job
            except Exception as exc:
                job.status = JobStatus.failed
                job.error = str(exc)
                job.updated_at = utc_now_iso()
                storage.save_job(job)
                self._emit_event(job_id, 'job.failed', {'error': str(exc)})
                raise

    def _start_watchers(self, runtime: JobRuntime) -> None:
        runtime.metrics_thread = threading.Thread(target=self._metrics_loop, args=(runtime,), daemon=True)
        runtime.artifact_thread = threading.Thread(target=self._artifact_loop, args=(runtime,), daemon=True)
        runtime.metrics_thread.start()
        runtime.artifact_thread.start()

    def _emit_event(self, job_id: str, event_type: str, payload: dict[str, Any]) -> None:
        event = EventMessage(event_type=event_type, job_id=job_id, timestamp=utc_now_iso(), payload=payload)
        runtime = self._jobs[job_id]
        runtime.storage.append_event(event.model_dump(mode='json'))
        self._emit(f'events:{job_id}', event.model_dump(mode='json'))

    def _stats_to_metrics(self, stats: dict[str, str], stats_file_path: str | None) -> Metrics:
        return Metrics(
            timestamp=utc_now_iso(),
            cycles_done=_to_int(stats.get('cycles_done')),
            execs_done=_to_int(stats.get('execs_done')),
            pending_total=_to_int(stats.get('pending_total')),
            unique_crashes=_to_int(stats.get('unique_crashes')),
            unique_hangs=_to_int(stats.get('unique_hangs')),
            bitmap_cvg=_to_float(stats.get('bitmap_cvg') or stats.get('t_bits(branch)')),
            stability=_to_float(stats.get('stability')) if stats.get('stability') is not None else None,
            stats_file_path=stats_file_path,
            raw=stats,
        )

    def _metrics_loop(self, runtime: JobRuntime) -> None:
        cfg = self.config_store.get()
        interval = cfg.afl.stats_history_interval_sec
        while not runtime.stop_event.is_set():
            stats_file = guess_stats_file(Path(runtime.job.output_dir).resolve())
            if stats_file:
                runtime.job.stats_file_path = str(stats_file)
                stats = parse_fuzzer_stats(stats_file)
                metrics = self._stats_to_metrics(stats, str(stats_file))
                runtime.job.last_metrics = metrics
                runtime.job.updated_at = utc_now_iso()
                runtime.storage.append_metrics(metrics)
                runtime.storage.save_job(runtime.job)
                snapshot = metrics.model_dump(mode='json')
                append_history_db(runtime.storage.db_file, snapshot)
                self._emit(f'metrics:{runtime.job.job_id}', snapshot)
            if not runtime.engine.is_running() and runtime.job.status == JobStatus.running:
                runtime.job.status = JobStatus.finished
                runtime.job.updated_at = utc_now_iso()
                runtime.storage.save_job(runtime.job)
                self._emit_event(runtime.job.job_id, 'job.finished', {'return_codes': runtime.engine.return_codes()})
                runtime.stop_event.set()
                return
            runtime.stop_event.wait(interval)

    def _artifact_loop(self, runtime: JobRuntime) -> None:
        cfg = self.config_store.get()
        interval = cfg.afl.artifact_scan_interval_sec
        while not runtime.stop_event.is_set():
            artifacts = self._scan_artifacts(Path(runtime.job.output_dir).resolve())
            changed = False
            for artifact in artifacts:
                if artifact.artifact_id not in runtime.known_artifacts:
                    runtime.known_artifacts[artifact.artifact_id] = artifact
                    changed = True
                    self._emit_event(runtime.job.job_id, 'artifact.discovered', artifact.model_dump(mode='json'))
                    self._emit(f'artifacts:{runtime.job.job_id}', artifact.model_dump(mode='json'))
            if changed:
                runtime.storage.save_artifacts(list(runtime.known_artifacts.values()))
            runtime.stop_event.wait(interval)

    def _scan_artifacts(self, output_dir: Path) -> list[ArtifactRecord]:
        found: list[ArtifactRecord] = []
        search_roots = [output_dir]
        if output_dir.exists():
            search_roots.extend(path for path in output_dir.iterdir() if path.is_dir())
        for root in search_roots:
            for kind_name, kind in (("crashes", ArtifactKind.crash), ("hangs", ArtifactKind.hang)):
                kind_dir = root / kind_name
                if not kind_dir.exists():
                    continue
                for path in kind_dir.iterdir():
                    if path.name.startswith('README') or not path.is_file():
                        continue
                    found.append(
                        ArtifactRecord(
                            artifact_id=path.name,
                            kind=kind,
                            path=str(path.resolve()),
                            size=path.stat().st_size,
                            discovered_at=utc_now_iso(),
                            source_dir=str(kind_dir.resolve()),
                        )
                    )
        return sorted(found, key=lambda x: x.path)

    def list_jobs(self) -> list[Job]:
        with self._lock:
            return [runtime.job for runtime in self._jobs.values()]

    def get_job(self, job_id: str) -> Job:
        return self._jobs[job_id].job

    def lookup_by_output(self, output_path: str) -> Job | None:
        key = str(Path(output_path).resolve())
        job_id = self._jobs_by_output.get(key)
        if not job_id:
            return None
        return self._jobs[job_id].job

    def lookup_by_pid(self, pid: int) -> Job | None:
        for runtime in self._jobs.values():
            if pid in runtime.job.pids:
                return runtime.job
        return None

    def stop_job(self, job_id: str) -> Job:
        runtime = self._jobs[job_id]
        if runtime.job.status in {JobStatus.finished, JobStatus.failed}:
            return runtime.job
        runtime.job.status = JobStatus.stopping
        runtime.job.updated_at = utc_now_iso()
        runtime.storage.save_job(runtime.job)
        runtime.stop_event.set()
        runtime.engine.stop()
        runtime.job.status = JobStatus.finished
        runtime.job.updated_at = utc_now_iso()
        runtime.storage.save_job(runtime.job)
        self._emit_event(job_id, 'job.stopped', {'pids': runtime.job.pids})
        return runtime.job

    def get_metrics(self, job_id: str) -> Metrics | None:
        runtime = self._jobs[job_id]
        if runtime.job.last_metrics is not None:
            return runtime.job.last_metrics
        stats_file = guess_stats_file(Path(runtime.job.output_dir).resolve())
        if not stats_file:
            return None
        stats = parse_fuzzer_stats(stats_file)
        return self._stats_to_metrics(stats, str(stats_file))

    def get_metrics_history(self, job_id: str, limit: int = 200) -> list[dict]:
        runtime = self._jobs[job_id]
        return read_history_db(runtime.storage.db_file, limit=limit)

    def list_artifacts(self, job_id: str) -> list[ArtifactRecord]:
        runtime = self._jobs[job_id]
        return list(runtime.known_artifacts.values())

    def get_artifact(self, job_id: str, artifact_id: str) -> ArtifactRecord:
        runtime = self._jobs[job_id]
        return runtime.known_artifacts[artifact_id]

    def replay_artifact(self, job_id: str, artifact_id: str) -> AnalysisResult:
        artifact = self.get_artifact(job_id, artifact_id)
        return AnalysisResult(artifact_id=artifact.artifact_id, status=ReplayStatus.succeeded, mode='replay', summary=f'replay placeholder for {artifact.path}')

    def analyze_artifact(self, job_id: str, artifact_id: str) -> AnalysisResult:
        artifact = self.get_artifact(job_id, artifact_id)
        return AnalysisResult(artifact_id=artifact.artifact_id, status=ReplayStatus.succeeded, mode='analyze', summary=f'analysis placeholder for {artifact.path}')

    def get_logs_tail(self, job_id: str, limit: int = 100) -> list[str]:
        runtime = self._jobs[job_id]
        return tail_lines(runtime.storage.log_file, limit=limit)

    def get_log_file(self, job_id: str) -> str:
        runtime = self._jobs[job_id]
        return str(runtime.storage.log_file)

    def system_info(self) -> dict[str, Any]:
        cfg = self.config_store.get()
        return {
            'jobs_running': sum(1 for item in self._jobs.values() if item.job.status == JobStatus.running),
            'jobs_total': len(self._jobs),
            'uds_path': cfg.server.uds.path,
            'http': {'host': cfg.server.http.host, 'port': cfg.server.http.port},
            'afl': {
                'configured_binary': cfg.afl.afl_binary,
                'search_paths': cfg.afl.binary_search_paths,
                'resolved_tools': resolve_afl_tools(cfg),
            },
        }

    def capabilities(self) -> dict[str, Any]:
        return {
            'offline': ['protocol.analyze', 'seeds.generate', 'risk.analyze', 'risk.preview', 'instrument'],
            'jobs': ['create', 'list', 'get', 'stop', 'metrics', 'artifacts', 'logs.tail'],
            'config': ['get', 'patch'],
        }
