from __future__ import annotations
import re
from pathlib import Path

class PathResolver:
    SUBDIRS = [
        "specs", "vuldocs/raw", "vuldocs/distilled", "vuldocs/chunks", "kb",
        "seeds/text", "seeds/bin", "risk/analyses", "risk/previews",
        "risk/instrumented", "debug/sessions", "debug/poc", "debug/reports",
        "history/vulns", "jobs"
    ]

    def __init__(self, workspace_root: str, default_protocol: str = "legacy-default"):
        self.root = Path(workspace_root).resolve()
        self.default_protocol = self.slugify(default_protocol)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "protocols").mkdir(parents=True, exist_ok=True)

    @staticmethod
    def slugify(value: str | None) -> str:
        raw = (value or "legacy-default").strip().lower()
        raw = re.sub(r"[^a-z0-9_.-]+", "-", raw).strip("-")
        return raw or "legacy-default"

    def protocol_root(self, protocol: str | None = None) -> Path:
        proto = self.slugify(protocol or self.default_protocol)
        root = self.root / "protocols" / proto
        for rel in self.SUBDIRS:
            (root / rel).mkdir(parents=True, exist_ok=True)
        return root

    def protocol(self, protocol: str | None = None) -> str:
        return self.slugify(protocol or self.default_protocol)

    def subdir(self, protocol: str | None, rel: str) -> Path:
        p = self.protocol_root(protocol) / rel
        p.mkdir(parents=True, exist_ok=True)
        return p

    def file(self, protocol: str | None, rel: str, name: str) -> Path:
        d = self.subdir(protocol, rel)
        return d / name

    def safe_filename(self, filename: str) -> str:
        name = Path(filename or "upload.bin").name
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)[:160] or "upload.bin"

    def job_root(self, protocol: str | None, job_id: str) -> Path:
        return self.subdir(protocol, "jobs") / job_id
