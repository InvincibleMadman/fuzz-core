from __future__ import annotations

from .config import ConfigStore
from .models import InstrumentRequest, ProtocolAnalyzeRequest, RiskAnalyzeRequest, RiskPreviewRequest, SeedGenerateRequest
from .offline.instrument import InstrumentationService
from .offline.protocol import ProtocolSpecService
from .offline.risk import RiskAnalysisService
from .offline.seeds import SeedService
from .runner.manager import JobManager
from .runner.models import JobCreateRequest


class LocalCoreClient:
    """Direct in-process API for local Python callers.

    TypeScript callers should use the official UDS SDK under packages/fuzz-core-client-ts.
    """

    def __init__(self, config_store: ConfigStore, manager: JobManager, protocol: ProtocolSpecService, seeds: SeedService, risk: RiskAnalysisService, instrument: InstrumentationService) -> None:
        self.config_store = config_store
        self.manager = manager
        self.protocol = protocol
        self.seeds = seeds
        self.risk = risk
        self.instrument = instrument

    def get_config(self) -> dict:
        return self.config_store.as_dict()

    def patch_config(self, patch: dict) -> dict:
        return self.config_store.update(patch).model_dump(mode='python')

    def analyze_protocol(self, req: ProtocolAnalyzeRequest | dict) -> dict:
        if isinstance(req, dict):
            req = ProtocolAnalyzeRequest.model_validate(req)
        return self.protocol.analyze_source(
            req.source_path,
            req.output_path,
            req.protocol_name,
            req.copy_to_scan_dir,
            lang=req.lang,
            implementation=req.implementation,
            protocol_style=req.protocol_style,
            profile=req.profile,
            protocol_variant=req.protocol_variant,
            iterations=req.iterations,
            temperature=req.temperature,
            max_tokens=req.max_tokens,
            base_url=req.base_url,
            api_key=req.api_key,
            model=req.model,
        )

    def generate_seeds(self, req: SeedGenerateRequest | dict) -> dict:
        if isinstance(req, dict):
            req = SeedGenerateRequest.model_validate(req)
        return self.seeds.generate(req.spec_path, req.spec_dir, req.output_dir, req.count, req.binary, req.issue_doc_dir, req.use_uploaded_vuldocs)

    def analyze_risk(self, req: RiskAnalyzeRequest | dict) -> dict:
        if isinstance(req, dict):
            req = RiskAnalyzeRequest.model_validate(req)
        return self.risk.analyze(
            req.source_path,
            req.output_path,
            req.copy_to_scan_dir,
            iterations=req.iterations,
            temperature_coefficient=req.temperature_coefficient,
            max_tokens=req.max_tokens,
        )

    def preview_risk(self, req: RiskPreviewRequest | dict | None = None) -> dict:
        if req is None:
            return self.risk.preview(None)
        if isinstance(req, dict):
            req = RiskPreviewRequest.model_validate(req)
        return self.risk.preview(req.analysis_path)

    def instrument_source(self, req: InstrumentRequest | dict) -> dict:
        if isinstance(req, dict):
            req = InstrumentRequest.model_validate(req)
        return self.instrument.instrument(req.source_path, req.analysis_path, req.output_path, req.in_place)

    def create_job(self, req: JobCreateRequest | dict):
        if isinstance(req, dict):
            req = JobCreateRequest.model_validate(req)
        return self.manager.create_job(req)

    def stop_job(self, job_id: str):
        return self.manager.stop_job(job_id)
