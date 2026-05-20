from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field
from ..models import now_iso

class TargetConfig(BaseModel):
    binary_path: str | None = None
    cwd: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str,str] = Field(default_factory=dict)
    protocol: str = "legacy-default"
    transport_type: Literal["udp","tcp","stdin","file","custom"] = "stdin"
    transport_config: dict[str, Any] = Field(default_factory=dict)
    startup_timeout: float = 3.0
    ready_check: dict[str, Any] = Field(default_factory=dict)

class DebugRequest(BaseModel):
    protocol: str = "legacy-default"
    target: TargetConfig = Field(default_factory=TargetConfig)
    artifact_path: str | None = None
    artifact_id: str | None = None
    job_id: str | None = None
    operation_id: str | None = None
    kb_entry_ids: list[str] = Field(default_factory=list)
    source_doc_ids: list[str] = Field(default_factory=list)

class DebugSession(BaseModel):
    session_id: str
    protocol: str
    status: str = "created"
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)
    request: dict[str, Any]
    states: list[dict[str, Any]] = Field(default_factory=list)
    gdb_context: dict[str, Any] = Field(default_factory=dict)
    classification: dict[str, Any] = Field(default_factory=dict)
    history_record_id: str | None = None
    report_path: str | None = None
