from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ApiEnvelope(BaseModel):
    is_success: bool = True
    success: bool = True
    code: int = 200
    msg: str = "ok"
    data: Any = None


class ConfigPatchRequest(BaseModel):
    patch: dict[str, Any]


class ProtocolAnalyzeRequest(BaseModel):
    source_path: str
    output_path: str | None = None
    protocol_name: str | None = None
    copy_to_scan_dir: bool = False
    lang: str = "c"
    implementation: str = ""
    protocol_style: str = "auto"
    profile: str = "auto"
    protocol_variant: str = ""
    iterations: int | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None


class SeedGenerateRequest(BaseModel):
    spec_path: str | None = None
    spec_dir: str | None = None
    output_dir: str | None = None
    count: int = 8
    binary: bool = False
    issue_doc_dir: str | None = None
    use_uploaded_vuldocs: bool = False


class RiskAnalyzeRequest(BaseModel):
    source_path: str
    output_path: str | None = None
    copy_to_scan_dir: bool = False
    iterations: int | None = None
    temperature_coefficient: float | None = None
    max_tokens: int | None = None


class RiskPreviewRequest(BaseModel):
    analysis_path: str | None = None


class InstrumentRequest(BaseModel):
    source_path: str | None = None
    analysis_path: str | None = None
    output_path: str | None = None
    in_place: bool = False


class FileSaveResult(BaseModel):
    path: str
    size: int


class ConfigResponse(BaseModel):
    config: dict[str, Any]
