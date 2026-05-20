from __future__ import annotations
from ..models import VulnHistoryRecord
from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository

class HistoryService:
    def __init__(self, paths: PathResolver, repo: Repository):
        self.paths, self.repo=paths, repo

    def archive(self, rec: dict):
        record=VulnHistoryRecord(**rec).model_dump()
        self.repo.upsert_history(record)
        return record

    def list(self, protocol: str, coarse_type: str|None=None, limit: int=100, offset: int=0):
        return self.repo.list_history(self.paths.protocol(protocol), coarse_type, limit, offset)

    def get(self, record_id: str):
        return self.repo.get_history(record_id)
