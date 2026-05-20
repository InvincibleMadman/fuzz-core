from dataclasses import dataclass
from .config import AppConfig
from .storage.path_resolver import PathResolver
from .storage.repository import Repository

@dataclass
class CoreState:
    config: AppConfig
    paths: PathResolver
    repo: Repository
    vuldocs: object
    distill: object
    kb: object
    seeds: object
    risk: object
    history: object
    debugger: object
    runner: object
    operations: object
