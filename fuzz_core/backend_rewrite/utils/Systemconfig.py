from __future__ import annotations

from dataclasses import dataclass

from ...config import ConfigStore


@dataclass
class LegacySystemConfigSnapshot:
    ISSUEDOC_PATH: str
    DISTILL_OUT_PATH: str
    INIT_SEED_TXT: str
    BIN_SEED_PATH: str
    RISK_OUT_PATH: str
    LLM_BASE_URL: str
    LLM_API_KEY: str
    SummIssue_MODEL: str
    Vulnlocator_MODEL: str


def build_snapshot(config_store: ConfigStore) -> LegacySystemConfigSnapshot:
    cfg = config_store.get()
    return LegacySystemConfigSnapshot(
        ISSUEDOC_PATH=cfg.legacy_paths.vuldoc_upload_dir,
        DISTILL_OUT_PATH=cfg.legacy_paths.distill_dir,
        INIT_SEED_TXT=cfg.legacy_paths.init_seed_txt_dir,
        BIN_SEED_PATH=cfg.legacy_paths.bin_seed_dir,
        RISK_OUT_PATH=cfg.legacy_paths.risk_output_dir,
        LLM_BASE_URL=cfg.llm.base_url,
        LLM_API_KEY=cfg.llm.api_key,
        SummIssue_MODEL=cfg.llm.models.seed_generation,
        Vulnlocator_MODEL=cfg.llm.models.risk_analysis,
    )
