from __future__ import annotations
from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository
from .kb_service import KBService

class ProtocolService:
    def __init__(self, paths: PathResolver, repo: Repository, kb: KBService):
        self.paths, self.repo, self.kb = paths, repo, kb

    def list_protocols(self):
        found=set(self.repo.protocols())
        protodir=self.paths.root/"protocols"
        if protodir.exists():
            found.update(p.name for p in protodir.iterdir() if p.is_dir())
        return sorted(found)

    def summary(self, protocol: str):
        proto=self.paths.protocol(protocol)
        return {
            "protocol": proto,
            "root": str(self.paths.protocol_root(proto)),
            "vuldoc_count": len(self.repo.list_vuldocs(proto, limit=10000)),
            "kb": self.kb.summary(proto),
            "risk_analysis_count": len(list(self.paths.subdir(proto, "risk/analyses").glob("*"))),
            "debug_session_count": len(self.repo.list_debug_sessions(proto, limit=10000)),
            "history_count": len(self.repo.list_history(proto, limit=10000)),
        }
