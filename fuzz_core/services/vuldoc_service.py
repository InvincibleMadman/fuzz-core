from __future__ import annotations
import hashlib, uuid
from pathlib import Path
from typing import Iterable
from fastapi import UploadFile
from ..models import VulDocRecord
from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository

class VulDocService:
    def __init__(self, paths: PathResolver, repo: Repository):
        self.paths, self.repo = paths, repo

    async def upload(self, protocol: str|None, files: Iterable[UploadFile], source: str="upload", metadata: dict|None=None):
        proto = self.paths.protocol(protocol)
        results=[]
        for f in files:
            content = await f.read()
            digest = hashlib.sha256(content).hexdigest()
            doc_id = f"doc-{uuid.uuid4().hex[:12]}"
            fname = f"{doc_id}-{self.paths.safe_filename(f.filename or 'vuldoc.txt')}"
            path = self.paths.file(proto, "vuldocs/raw", fname)
            path.write_bytes(content)
            rec = VulDocRecord(doc_id=doc_id, protocol=proto, filename=f.filename or fname, raw_path=str(path), sha256=digest, size=len(content), source=source, metadata=metadata or {}).model_dump()
            self.repo.upsert_vuldoc(rec)
            (path.with_suffix(path.suffix + ".metadata.json")).write_text(__import__("json").dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
            results.append(rec)
        return results

    def list(self, protocol: str, limit: int=100, offset: int=0):
        return self.repo.list_vuldocs(self.paths.protocol(protocol), limit, offset)

    def get(self, doc_id: str):
        return self.repo.get_vuldoc(doc_id)
