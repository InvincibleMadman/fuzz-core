
from __future__ import annotations

from dataclasses import dataclass

from .config import ConfigStore
from .offline.instrument import InstrumentationService
from .offline.protocol import ProtocolSpecService
from .offline.risk import RiskAnalysisService
from .offline.seeds import SeedService
from .runner.manager import JobManager
from .sdk import LocalCoreClient


@dataclass
class AppState:
    config_store: ConfigStore
    manager: JobManager
    protocol_service: ProtocolSpecService
    seed_service: SeedService
    risk_service: RiskAnalysisService
    instrument_service: InstrumentationService
    local_client: LocalCoreClient
