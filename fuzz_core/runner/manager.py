from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from .models import JobCreate, JobRecord
from .storage import JobStorage
from ..debugger.models import TargetConfig
from ..storage.path_resolver import PathResolver


class RunnerManager:
    def __init__(self, paths: PathResolver, debugger):
        self.paths = paths
        self.debugger = debugger
        self.storage = JobStorage(self.paths.root / "jobs")

    def create_job(self, req: JobCreate | dict):
        if isinstance(req, dict):
            req = JobCreate.model_validate(req)
        proto = self.paths.protocol(req.protocol)
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        out = Path(req.output_dir) if req.output_dir else self.paths.job_root(proto, job_id) / "outputs"
        out.mkdir(parents=True, exist_ok=True)
        job = JobRecord(
            job_id=job_id,
            protocol=proto,
            status="finished" if req.dry_run else "running",
            request=req.model_dump(),
            output_dir=str(out),
            metrics={"execs_done": 0, "unique_crashes": 0},
        ).model_dump()
        self.storage.save(job)
        return job

    def list_jobs(self):
        return self.storage.list()

    def get_job(self, job_id: str):
        return self.storage.get(job_id)

    def stop_job(self, job_id: str):
        job = self.storage.get(job_id)
        if not job:
            return None
        job["status"] = "stopped"
        self.storage.save(job)
        return job

    def metrics(self, job_id: str):
        job = self.storage.get(job_id) or {}
        out = Path(job.get("output_dir", ""))
        stats = {}
        for p in out.rglob("fuzzer_stats") if out.exists() else []:
            for ln in p.read_text(errors="ignore").splitlines():
                if ":" in ln:
                    k, v = [x.strip() for x in ln.split(":", 1)]
                    stats[k] = v
        return {"job_id": job_id, **(job.get("metrics") or {}), "fuzzer_stats": stats}

    def metrics_history(self, job_id: str):
        return {"job_id": job_id, "points": []}

    def _artifact_candidates(self, job):
        out = Path(job.get("output_dir", ""))
        items = []
        if out.exists():
            for p in list(out.rglob("crashes/*")) + list(out.rglob("hangs/*")):
                if p.is_file() and not p.name.startswith("README"):
                    items.append(p)
        return items

    def stable_artifact_id(self, job_id: str, path: str | Path) -> str:
        # Stable across Python processes and backend restarts. Including job_id avoids
        # collisions when two jobs point to different mounted paths with the same name.
        payload = f"{job_id}:{Path(path).resolve(strict=False)}".encode("utf-8")
        return "artifact-" + hashlib.sha256(payload).hexdigest()[:16]

    def artifacts(self, job_id: str):
        job = self.storage.get(job_id)
        if not job:
            return []
        items = []
        for p in self._artifact_candidates(job):
            aid = self.stable_artifact_id(job_id, p)
            item = {
                "job_id": job_id,
                "artifact_id": aid,
                "path": str(p),
                "seed_path": str(p),
                "name": p.name,
                "kind": "crash" if "crashes" in p.parts else "hang",
                "size": p.stat().st_size,
                "protocol": job["protocol"],
                "target": self._target_from_job(job).model_dump(),
                "debug_session_request": self._debug_request_template(job, aid, p),
            }
            items.append(item)
        return items

    def get_artifact(self, job_id: str, artifact_id: str):
        for a in self.artifacts(job_id):
            if a["artifact_id"] == artifact_id:
                return a
        return None

    def debug_candidates(self, job_id: str | None = None):
        jobs = [self.storage.get(job_id)] if job_id else self.storage.list()
        items = []
        for job in jobs:
            if not job:
                continue
            items.extend(self.artifacts(job["job_id"]))
        return items

    def replay_artifact(self, job_id: str, artifact_id: str):
        art = self.get_artifact(job_id, artifact_id)
        job = self.storage.get(job_id)
        if not art or not job:
            return None
        target = self._target_from_job(job)
        res = self.debugger.replayer.replay(target, art["path"])
        return {"job_id": job_id, "artifact_id": artifact_id, "protocol": job["protocol"], "seed_path": art["path"], "replay": res}

    def analyze_artifact(self, job_id: str, artifact_id: str):
        """Preserve the historic route without starting GDB.

        GDB is now a standalone API under /api/v1/debug/sessions. This method
        returns the exact crash seed and target variables a UI needs to launch
        that API explicitly after a user selects the artifact.
        """
        art = self.get_artifact(job_id, artifact_id)
        job = self.storage.get(job_id)
        if not art or not job:
            return None
        return {
            "job_id": job_id,
            "artifact_id": artifact_id,
            "protocol": job["protocol"],
            "seed_path": art["path"],
            "target": self._target_from_job(job).model_dump(),
            "gdb_binding_removed": True,
            "message": "This job artifact endpoint no longer starts GDB. Use POST /api/v1/debug/sessions with debug_session_request.",
            "debug_session_request": self._debug_request_template(job, artifact_id, Path(art["path"])),
        }

    def _debug_request_template(self, job: dict, artifact_id: str, path: Path) -> dict:
        return {
            "protocol": job["protocol"],
            "artifact_path": str(path),
            "artifact_id": artifact_id,
            "job_id": job["job_id"],
            "target": self._target_from_job(job).model_dump(),
        }

    def _target_from_job(self, job):
        r = job.get("request") or {}
        cmd = r.get("target_cmd") or []
        binary = cmd[0] if cmd else None
        return TargetConfig(
            protocol=job["protocol"],
            binary_path=binary,
            cwd=r.get("cwd"),
            args=cmd[1:],
            transport_type=(r.get("debug") or {}).get("transport_type", "stdin"),
            transport_config=(r.get("debug") or {}).get("transport_config", {}),
        )
