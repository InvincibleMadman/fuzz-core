from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from ..models import now_iso


class OperationLogService:
    """Protocol-aware, file-backed operation logging for frontend progress views.

    The service is intentionally simple and local-only: every operation is a JSONL
    file under workspace/operations. Existing synchronous APIs can accept an
    operation_id supplied by the frontend before the request starts; the frontend
    can poll tail endpoints while the request is running.
    """

    def __init__(self, workspace_root: Path | str):
        self.root = Path(workspace_root) / "operations"
        self.root.mkdir(parents=True, exist_ok=True)

    def start(self, kind: str, protocol: str = "legacy-default", operation_id: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        op_id = operation_id or f"op-{uuid.uuid4().hex[:12]}"
        rec = {
            "operation_id": op_id,
            "kind": kind,
            "protocol": protocol or "legacy-default",
            "status": "running",
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "metadata": metadata or {},
        }
        self._meta_path(op_id).write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
        self.append(op_id, "started", f"Started {kind}", {"kind": kind, "protocol": rec["protocol"]})
        return rec

    def append(self, operation_id: str, stage: str, message: str, data: dict[str, Any] | None = None, level: str = "info") -> dict[str, Any]:
        event = {
            "operation_id": operation_id,
            "at": now_iso(),
            "level": level,
            "stage": stage,
            "message": message,
            "data": data or {},
        }
        with self._log_path(operation_id).open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
        meta = self.get(operation_id)
        if meta:
            meta["updated_at"] = event["at"]
            self._meta_path(operation_id).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return event

    def finish(self, operation_id: str, status: str = "finished", result: dict[str, Any] | None = None) -> dict[str, Any]:
        self.append(operation_id, status, f"Operation {status}", result or {}, level="info" if status == "finished" else "error")
        meta = self.get(operation_id) or {"operation_id": operation_id}
        meta["status"] = status
        meta["updated_at"] = now_iso()
        if result is not None:
            meta["result"] = result
        self._meta_path(operation_id).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return meta

    def fail(self, operation_id: str, error: Exception | str) -> dict[str, Any]:
        return self.finish(operation_id, "failed", {"error": str(error)})

    def get(self, operation_id: str) -> dict[str, Any] | None:
        p = self._meta_path(operation_id)
        if not p.exists():
            return None
        return json.loads(p.read_text(encoding="utf-8"))

    def list(self, kind: str | None = None, protocol: str | None = None, status: str | None = None, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for p in self.root.glob("*.meta.json"):
            try:
                item = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if kind and item.get("kind") != kind:
                continue
            if protocol and item.get("protocol") != protocol:
                continue
            if status and item.get("status") != status:
                continue
            items.append(item)
        items.sort(key=lambda x: x.get("updated_at") or x.get("created_at") or "", reverse=True)
        return items[offset:offset + limit]

    def tail(self, operation_id: str, since: int = 0, limit: int = 200) -> dict[str, Any]:
        p = self._log_path(operation_id)
        lines: list[dict[str, Any]] = []
        if p.exists():
            raw = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, line in enumerate(raw[since:since + limit], start=since):
                try:
                    item = json.loads(line)
                except Exception:
                    item = {"operation_id": operation_id, "at": "", "level": "info", "stage": "raw", "message": line, "data": {}}
                item["seq"] = idx
                lines.append(item)
        meta = self.get(operation_id)
        next_seq = since + len(lines)
        return {
            "operation_id": operation_id,
            "status": (meta or {}).get("status", "unknown"),
            "next_seq": next_seq,
            "items": lines,
        }

    def _meta_path(self, operation_id: str) -> Path:
        return self.root / f"{self._safe(operation_id)}.meta.json"

    def _log_path(self, operation_id: str) -> Path:
        return self.root / f"{self._safe(operation_id)}.jsonl"

    def _safe(self, name: str) -> str:
        return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:160]
