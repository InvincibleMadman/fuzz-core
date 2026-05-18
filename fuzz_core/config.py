from __future__ import annotations

import copy
import os
import threading
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class HttpConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 18000


class UdsConfig(BaseModel):
    enabled: bool = True
    path: str = "/tmp/fuzz-core.sock"


class CorsConfig(BaseModel):
    enabled: bool = False
    allow_origins: list[str] = Field(default_factory=list)
    allow_origin_regex: str | None = None
    allow_credentials: bool = True
    allow_methods: list[str] = Field(default_factory=lambda: ["GET", "POST", "PATCH", "OPTIONS"])
    allow_headers: list[str] = Field(default_factory=lambda: ["Authorization", "Content-Type"])
    expose_headers: list[str] = Field(default_factory=list)
    max_age: int = 3600


class ServerConfig(BaseModel):
    http: HttpConfig = Field(default_factory=HttpConfig)
    uds: UdsConfig = Field(default_factory=UdsConfig)
    cors: CorsConfig = Field(default_factory=CorsConfig)


class ModelConfig(BaseModel):
    protocol_extract: str = "gpt-5.4"
    risk_analysis: str = "gpt-5.4"
    seed_generation: str = "gpt-5.4"


class LLMConfig(BaseModel):
    provider: str = "openai-compatible"
    base_url: str = "https://api.vectorengine.ai/v1"
    api_key: str = ""
    models: ModelConfig = Field(default_factory=ModelConfig)
    timeout_sec: int = 120


class PathsConfig(BaseModel):
    workspace: str = "./workspace"
    uploads_dir: str = "./workspace/uploads"
    protocol_dir: str = "./workspace/protocol_specs"
    seed_dir: str = "./workspace/seeds"
    risk_dir: str = "./workspace/risk_results"
    jobs_dir: str = "./workspace/jobs"
    logs_dir: str = "./workspace/logs"
    temp_dir: str = "./workspace/tmp"
    protocol_scan_dir: str = "./workspace/protocol_specs"
    risk_scan_dir: str = "./workspace/risk_results"


class LegacyBackendPathsConfig(BaseModel):
    vuldoc_upload_dir: str = "./workspace/uploads/Vuldoc"
    risk_upload_dir: str = "./workspace/uploads/Riskresult"
    distill_dir: str = "./workspace/corpus/distill"
    init_seed_txt_dir: str = "./workspace/corpus/queue"
    bin_seed_dir: str = "./workspace/corpus/bin_seed"
    risk_output_dir: str = "./workspace/corpus/risk_analy_result"
    protocol_output_dir: str = "./workspace/extract/output/best"


class RuntimeConfig(BaseModel):
    preeny_desock_path: str = "/home/zyl/preeny/src/desock.so"
    use_preeny_desock: bool = False
    afl_default_memory: str = "none"


class AFLRuntimeConfig(BaseModel):
    afl_binary: str = "afl-fuzz"
    binary_search_paths: list[str] = Field(default_factory=lambda: ["afl-fuzz", "/usr/local/bin/afl-fuzz", "/usr/bin/afl-fuzz"])
    compiler_binaries: list[str] = Field(default_factory=lambda: ["afl-clang-fast", "afl-clang-lto", "afl-cc", "afl-showmap"])
    default_workers: int = 1
    default_fuzzer_args: list[str] = Field(default_factory=list)
    default_env: dict[str, str] = Field(default_factory=dict)
    poll_interval_sec: float = 2.0
    artifact_scan_interval_sec: float = 5.0
    stats_history_interval_sec: float = 5.0
    replay_timeout_sec: int = 30


class OfflineDefaultsConfig(BaseModel):
    default_protocol_filename: str = "protocol_spec.json"
    default_risk_filename: str = "final_analysis.json"
    default_seed_count: int = 8
    risk_preview_chars: int = 12000


class AppConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    legacy_paths: LegacyBackendPathsConfig = Field(default_factory=LegacyBackendPathsConfig)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    afl: AFLRuntimeConfig = Field(default_factory=AFLRuntimeConfig)
    offline: OfflineDefaultsConfig = Field(default_factory=OfflineDefaultsConfig)


def _deep_update(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _deep_update(dst[key], value)
        else:
            dst[key] = value
    return dst


class ConfigStore:
    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path or os.environ.get("FUZZ_CORE_CONFIG", "./config.yaml"))
        self._lock = threading.RLock()
        self._config = self._load_or_init()
        self.ensure_dirs()

    def _load_or_init(self) -> AppConfig:
        if self.path.exists():
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
            return AppConfig.model_validate(raw)
        cfg = AppConfig()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(yaml.safe_dump(cfg.model_dump(mode="python"), sort_keys=False, allow_unicode=True), encoding="utf-8")
        return cfg

    def ensure_dirs(self) -> None:
        cfg = self.get()
        for value in cfg.paths.model_dump().values():
            Path(value).mkdir(parents=True, exist_ok=True)
        for value in cfg.legacy_paths.model_dump().values():
            Path(value).mkdir(parents=True, exist_ok=True)

    def get(self) -> AppConfig:
        with self._lock:
            return copy.deepcopy(self._config)

    def as_dict(self) -> dict[str, Any]:
        return self.get().model_dump(mode="python")

    def update(self, patch: dict[str, Any]) -> AppConfig:
        with self._lock:
            data = self._config.model_dump(mode="python")
            _deep_update(data, patch)
            self._config = AppConfig.model_validate(data)
            self.path.write_text(
                yaml.safe_dump(self._config.model_dump(mode="python"), sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            self.ensure_dirs()
            return copy.deepcopy(self._config)
