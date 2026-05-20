from __future__ import annotations

import json

from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository


class DebugPersistence:
    def __init__(self, paths: PathResolver, repo: Repository):
        self.paths, self.repo = paths, repo

    def save(self, session: dict):
        self.repo.save_debug_session(session)
        out = self.paths.file(session["protocol"], "debug/sessions", session["session_id"] + ".json")
        out.write_text(json.dumps(session, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(out)

    def save_report(self, session: dict, report: dict):
        out = self.paths.file(session["protocol"], "debug/reports", session["session_id"] + ".report.json")
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(out)

    def get(self, session_id: str):
        return self.repo.get_debug_session(session_id)

    def list(self, protocol: str, coarse_type: str | None = None, limit: int = 100, offset: int = 0):
        return self.repo.list_debug_sessions(self.paths.protocol(protocol), coarse_type, limit, offset)
