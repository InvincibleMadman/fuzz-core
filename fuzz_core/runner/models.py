
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    starting = "starting"
    running = "running"
    stopping = "stopping"
    finished = "finished"
    failed = "failed"


class ArtifactKind(str, Enum):
    crash = "crash"
    hang = "hang"


class ReplayStatus(str, Enum):
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"


class AFLConfigModel(BaseModel):
    afl_binary: str = "afl-fuzz"
    target_binary: str
    input_dir: str
    output_dir: str
    run_cwd: str | None = None
    source_dir: str | None = None
    build_dir: str | None = None
    target_args: list[str] = Field(default_factory=list)
    fuzzer_args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    workers: int = 1


class ReplayConfigModel(BaseModel):
    enabled: bool = True
    timeout_sec: int = 30
    env: dict[str, str] = Field(default_factory=dict)


class DebugConfigModel(BaseModel):
    enabled: bool = False
    command: list[str] = Field(default_factory=lambda: ["gdb", "--batch"])


class AnalysisPolicyModel(BaseModel):
    enabled: bool = True
    modes: list[str] = Field(default_factory=lambda: ["stdout", "basic"])


class JobCreateRequest(BaseModel):
    name: str | None = None
    afl: AFLConfigModel
    replay: ReplayConfigModel = Field(default_factory=ReplayConfigModel)
    debug: DebugConfigModel = Field(default_factory=DebugConfigModel)
    analysis_policy: AnalysisPolicyModel = Field(default_factory=AnalysisPolicyModel)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Metrics(BaseModel):
    timestamp: str
    cycles_done: int = 0
    execs_done: int = 0
    pending_total: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    bitmap_cvg: float = 0.0
    stability: float | None = None
    stats_file_path: str | None = None
    raw: dict[str, str] = Field(default_factory=dict)


class ArtifactRecord(BaseModel):
    artifact_id: str
    kind: ArtifactKind
    path: str
    size: int
    discovered_at: str
    source_dir: str


class AnalysisResult(BaseModel):
    artifact_id: str
    status: ReplayStatus
    mode: str
    stdout: str = ""
    stderr: str = ""
    summary: str = ""
    output_path: str | None = None


class Job(BaseModel):
    job_id: str
    name: str
    status: JobStatus
    created_at: str
    updated_at: str
    afl: AFLConfigModel
    replay: ReplayConfigModel
    debug: DebugConfigModel
    analysis_policy: AnalysisPolicyModel
    metadata: dict[str, Any] = Field(default_factory=dict)
    pids: list[int] = Field(default_factory=list)
    output_dir: str
    stats_file_path: str | None = None
    log_path: str | None = None
    db_path: str | None = None
    error: str | None = None
    last_metrics: Metrics | None = None


class EventMessage(BaseModel):
    event_type: str
    job_id: str
    timestamp: str
    payload: dict[str, Any] = Field(default_factory=dict)
