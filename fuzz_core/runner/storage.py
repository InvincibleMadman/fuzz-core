from __future__ import annotations
import json
from pathlib import Path

class JobStorage:
    def __init__(self, root: Path):
        self.root=root; self.root.mkdir(parents=True, exist_ok=True)

    def save(self, job: dict):
        path=self.root/(job["job_id"]+".json")
        path.write_text(json.dumps(job, ensure_ascii=False, indent=2), encoding="utf-8")

    def get(self, job_id: str):
        path=self.root/(job_id+".json")
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def list(self):
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.root.glob("*.json"))]
