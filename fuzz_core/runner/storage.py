
from __future__ import annotations

from pathlib import Path

from .models import ArtifactRecord, Job, Metrics
from ..utils.fs import append_jsonl, ensure_dir, read_json, tail_lines, write_json


class JobStorage:
    def __init__(self, root: Path) -> None:
        self.root = ensure_dir(root)
        self.logs_dir = ensure_dir(self.root / "logs")
        self.analysis_dir = ensure_dir(self.root / "analysis")
        self.job_file = self.root / "job.json"
        self.artifacts_file = self.root / "artifacts.json"
        self.events_file = self.root / "events.ndjson"
        self.metrics_history_file = self.root / "metrics-history.ndjson"
        self.log_file = self.logs_dir / "runner.log"
        self.db_file = self.root / "fuzzing_result.db"

    def save_job(self, job: Job) -> None:
        write_json(self.job_file, job.model_dump(mode="json"))

    def load_job(self) -> dict:
        return read_json(self.job_file)

    def save_artifacts(self, items: list[ArtifactRecord]) -> None:
        write_json(self.artifacts_file, {"artifacts": [item.model_dump(mode="json") for item in items]})

    def append_event(self, payload: dict) -> None:
        append_jsonl(self.events_file, payload)

    def append_metrics(self, metrics: Metrics) -> None:
        append_jsonl(self.metrics_history_file, metrics.model_dump(mode="json"))

    def tail_log(self, limit: int = 100) -> list[str]:
        return tail_lines(self.log_file, limit=limit)
