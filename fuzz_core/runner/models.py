from __future__ import annotations
from typing import Any
from pydantic import BaseModel, Field
from ..models import now_iso

class JobCreate(BaseModel):
    protocol: str = "legacy-default"
    cwd: str | None = None
    target_cmd: list[str] = Field(default_factory=list)
    afl_path: str | None = None
    input_dir: str | None = None
    output_dir: str | None = None
    timeout_sec: int | None = None
    dry_run: bool = True
    debug: dict[str, Any] = Field(default_factory=dict)

class JobRecord(BaseModel):
    job_id: str
    protocol: str
    status: str = "created"
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)
    request: dict[str, Any] = Field(default_factory=dict)
    output_dir: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
