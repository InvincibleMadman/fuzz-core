from __future__ import annotations
import os
from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field

class WorkspaceConfig(BaseModel):
    root: str = "./workspace"
    default_protocol: str = "legacy-default"

class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000

class LLMConfig(BaseModel):
    provider: str = "local"
    model: str = "local-rule-based"
    base_url: str = ""
    api_key_env: str = "FUZZ_CORE_LLM_API_KEY"

class PathConfig(BaseModel):
    afl_fuzz: str = "afl-fuzz"
    afl_showmap: str = "afl-showmap"
    preeny_desock: str = ""

class DebuggerConfig(BaseModel):
    gdb_path: str = "gdb"
    timeout_sec: int = 20
    allow_network_replay: bool = False

class AppConfig(BaseModel):
    workspace: WorkspaceConfig = Field(default_factory=WorkspaceConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    paths: PathConfig = Field(default_factory=PathConfig)
    debugger: DebuggerConfig = Field(default_factory=DebuggerConfig)

    @property
    def llm_api_key(self) -> str:
        return os.getenv(self.llm.api_key_env, "")

def load_config(path: str | None = None) -> AppConfig:
    config_path = path or os.getenv("FUZZ_CORE_CONFIG", "config.yaml")
    if Path(config_path).exists():
        data: dict[str, Any] = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    else:
        data = {}
    return AppConfig.model_validate(data)

def save_config(cfg: AppConfig, path: str | None = None) -> None:
    config_path = Path(path or os.getenv("FUZZ_CORE_CONFIG", "config.yaml"))
    config_path.write_text(yaml.safe_dump(cfg.model_dump(), allow_unicode=True, sort_keys=False), encoding="utf-8")
