from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from .classifier import VulnerabilityClassifier
from .gdb_driver import GDBDriver
from .models import DebugRequest, DebugSession
from .persistence import DebugPersistence
from .replayer import Replayer
from ..services.history_service import HistoryService


def now():
    return datetime.now(timezone.utc).isoformat()


class DebugSessionManager:
    STATES = [
        "created",
        "launching_target",
        "replaying_input",
        "waiting_signal",
        "collecting_context",
        "llm_reasoning",
        "classified",
        "archived",
    ]

    def __init__(
        self,
        gdb: GDBDriver,
        replayer: Replayer,
        classifier: VulnerabilityClassifier,
        persistence: DebugPersistence,
        history: HistoryService,
        operations=None,
    ):
        self.gdb = gdb
        self.replayer = replayer
        self.classifier = classifier
        self.persistence = persistence
        self.history = history
        self.operations = operations

    def run(self, req: DebugRequest | dict):
        if isinstance(req, dict):
            req = DebugRequest.model_validate(req)
        session = DebugSession(session_id=f"dbg-{uuid.uuid4().hex[:12]}", protocol=req.protocol, request=req.model_dump())
        self._step(session, "launching_target", {"binary_path": req.target.binary_path, "cwd": req.target.cwd})
        self._step(session, "replaying_input", self.replayer.replay(req.target, req.artifact_path))
        self._step(session, "waiting_signal", {})
        self._step(session, "collecting_context", {})
        ctx = self.gdb.collect(req.target, req.artifact_path)
        session.gdb_context = ctx
        self._step(session, "llm_reasoning", {"engine": "local-rule-based", "note": "No external LLM is required for local triage."})
        cls = self.classifier.classify(req.protocol, ctx, req.artifact_path, req.artifact_id)
        session.classification = cls
        self._step(session, "classified", cls)

        rec = {
            "record_id": f"vuln-{uuid.uuid4().hex[:12]}",
            "protocol": req.protocol,
            "coarse_type": cls.get("coarse_type", "unknown"),
            "vuln_type": cls.get("vuln_type", "unknown"),
            "cwe": cls.get("cwe", ""),
            "title": f"{req.protocol} {cls.get('vuln_type', 'unknown')} ({cls.get('crash_signature', '')})",
            "root_cause": cls.get("root_cause", ""),
            "direct_cause": cls.get("direct_cause", ""),
            "crash_signature": cls.get("crash_signature", ""),
            "file": cls.get("file", ""),
            "function": cls.get("function", ""),
            "line": cls.get("line"),
            "stack_summary": cls.get("stack_summary", ""),
            "repro_steps": cls.get("repro_steps", []),
            "poc_concept": cls.get("poc_concept", ""),
            "fix_suggestion": cls.get("fix_suggestion", ""),
            "confidence": cls.get("confidence", 0.4),
            "debug_session_id": session.session_id,
            "artifact_id": req.artifact_id,
            "source_doc_ids": req.source_doc_ids,
            "kb_entry_ids": req.kb_entry_ids,
            "metadata": {
                "artifact_path": req.artifact_path,
                "job_id": req.job_id,
                "target": req.target.model_dump(),
                "possible_exploitability": cls.get("possible_exploitability"),
            },
        }
        saved = self.history.archive(rec)
        session.history_record_id = saved["record_id"]
        self._step(session, "archived", {"history_record_id": session.history_record_id})

        session_dict = session.model_dump()
        debug_report = self._debug_report(session_dict, req, cls, ctx, saved)
        report_json_path = self.persistence.save_report(session_dict, debug_report)
        session_dict["debug_report"] = debug_report
        session_dict["debug_report_path"] = report_json_path
        session_dict["report_path"] = self.persistence.save(session_dict)
        # Save once more so report_path is persisted inside the session JSON and DB.
        self.persistence.save(session_dict)
        return session_dict

    def _debug_report(self, session: dict, req: DebugRequest, cls: dict, ctx: dict, history: dict) -> dict:
        line = cls.get("line")
        return {
            "schema_version": "debug-report.v1",
            "session_id": session["session_id"],
            "history_record_id": history.get("record_id"),
            "protocol": req.protocol,
            "job_id": req.job_id,
            "artifact": {
                "artifact_id": req.artifact_id,
                "seed_path": req.artifact_path,
                "seed_name": Path(req.artifact_path).name if req.artifact_path else None,
            },
            "target": req.target.model_dump(),
            "vulnerability_location": {
                "function_name": cls.get("function") or ctx.get("function_name") or "",
                "file_path": cls.get("file") or (ctx.get("source_location") or {}).get("file", ""),
                "line": line,
                "line_start": max(1, int(line) - 5) if isinstance(line, int) else None,
                "line_end": int(line) + 5 if isinstance(line, int) else None,
            },
            "error_type": cls.get("error_type") or cls.get("vuln_type") or "unknown",
            "vuln_type": cls.get("vuln_type", "unknown"),
            "coarse_type": cls.get("coarse_type", "unknown"),
            "cwe": cls.get("cwe", ""),
            "signal": ctx.get("signal", ""),
            "exit_code": ctx.get("exit_code"),
            "crash_signature": cls.get("crash_signature", ""),
            "root_cause": cls.get("root_cause", ""),
            "direct_cause": cls.get("direct_cause", ""),
            "possible_exploitation_description": cls.get("potential_exploitation_description") or cls.get("possible_exploitability") or "",
            "poc_concept": cls.get("poc_concept", ""),
            "repro_steps": cls.get("repro_steps", []),
            "fix_suggestion": cls.get("fix_suggestion", ""),
            "confidence": cls.get("confidence", 0.0),
            "stack_summary": cls.get("stack_summary", ""),
            "gdb_context_excerpt": {
                "backtrace": (ctx.get("backtrace") or "")[:4000],
                "frame_locals": (ctx.get("frame_locals") or "")[:2000],
                "registers": (ctx.get("registers") or "")[:2000],
                "stdout_stderr_tail": (ctx.get("stdout_stderr_tail") or "")[-2000:],
            },
            "created_at": session.get("created_at"),
            "updated_at": now(),
        }

    def _step(self, session: DebugSession, status: str, data: dict):
        session.status = status
        session.updated_at = now()
        session.states.append({"status": status, "at": session.updated_at, "data": data})
