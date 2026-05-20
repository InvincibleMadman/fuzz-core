from __future__ import annotations
import json, re, uuid
from pathlib import Path
from ..models import KBEntry, COARSE_TYPES
from ..storage.path_resolver import PathResolver
from ..storage.repository import Repository

class DistillService:
    KEYWORDS = [
        ("use-after-free", "use-after-free", "CWE-416", "memory-corruption"),
        ("null pointer", "null-deref", "CWE-476", "null-deref"),
        ("out-of-bounds", "out-of-bounds-read", "CWE-125", "bounds-check"),
        ("overflow", "buffer-overflow", "CWE-120", "memory-corruption"),
        ("integer", "integer-overflow", "CWE-190", "integer-issue"),
        ("state machine", "state-machine", "", "protocol-state-machine"),
        ("authentication", "auth-bypass", "CWE-287", "auth-logic"),
        ("dos", "denial-of-service", "CWE-400", "resource-exhaustion"),
    ]

    def __init__(self, paths: PathResolver, repo: Repository):
        self.paths, self.repo = paths, repo

    def _classify(self, text: str):
        low=text.lower()
        for key, vt, cwe, coarse in self.KEYWORDS:
            if key in low:
                return vt, coarse, cwe, 0.72
        if any(x in low for x in ["parse", "decode", "packet", "frame", "message"]):
            return "parser-bug", "parser-state", "", 0.55
        return "unknown", "unknown", "", 0.35

    def _extract_evidence(self, text: str):
        lines=[ln.strip() for ln in text.splitlines() if ln.strip()]
        scored=[]
        hints=["crash","overflow","out-of-bounds","null","uaf","use-after-free","parse","decode","poc","cwe","漏洞","越界","崩溃","复现"]
        for ln in lines:
            if any(h.lower() in ln.lower() for h in hints):
                scored.append(ln[:500])
        return scored[:8] or lines[:3]

    def distill_doc(self, doc_id: str):
        doc = self.repo.get_vuldoc(doc_id)
        if not doc:
            raise FileNotFoundError(doc_id)
        raw = Path(doc["raw_path"])
        text = raw.read_text(encoding="utf-8", errors="ignore") if raw.exists() else ""
        vuln_type, coarse_type, cwe, conf = self._classify(text)
        title = (text.strip().splitlines() or [doc["filename"]])[0][:160]
        func = ""
        m=re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
        if m: func=m.group(1)
        file_path = ""
        fm = re.search(r"([\w./-]+\.(?:c|cc|cpp|h|hpp|py|go|rs))", text)
        if fm: file_path=fm.group(1)
        entry = KBEntry(
            entry_id=f"kb-{uuid.uuid4().hex[:12]}", protocol=doc["protocol"], doc_id=doc_id,
            title=title or "Distilled vulnerability", summary=" ".join(self._extract_evidence(text))[:1200],
            source_ref=doc["filename"], vuln_type=vuln_type, coarse_type=coarse_type, cwe=cwe,
            trigger_condition=self._infer_trigger(text), input_shape=self._infer_shape(text),
            message_fields=self._infer_fields(text), function_name=func, file_path=file_path,
            evidence=self._extract_evidence(text), poc_hint=self._infer_poc(text),
            fix_hint="Add strict length/state validation before parsing user-controlled protocol data.",
            confidence=conf, tags=[coarse_type, vuln_type],
        ).model_dump()
        self.repo.upsert_kb_entry(entry)
        out = self.paths.file(doc["protocol"], "vuldocs/distilled", entry["entry_id"] + ".json")
        out.write_text(json.dumps(entry, ensure_ascii=False, indent=2), encoding="utf-8")
        return entry

    def distill_protocol(self, protocol: str, doc_ids: list[str]|None=None):
        proto=self.paths.protocol(protocol)
        docs=[self.repo.get_vuldoc(x) for x in doc_ids] if doc_ids else self.repo.list_vuldocs(proto, 1000, 0)
        return [self.distill_doc(d["doc_id"]) for d in docs if d]

    def _infer_trigger(self, text: str):
        low=text.lower()
        if "length" in low or "长度" in text: return "Malformed length/count field reaches parser without sufficient bounds validation."
        if "state" in low: return "Protocol state transition accepts an unexpected message sequence."
        return "Malformed protocol input reaches a vulnerable parser path."

    def _infer_shape(self, text: str):
        low=text.lower()
        if "udp" in low: return "UDP packet"
        if "tcp" in low: return "TCP stream/message"
        if "file" in low: return "file input"
        return "protocol message bytes"

    def _infer_fields(self, text: str):
        fields=[]
        for k in ["length","count","type","opcode","function","service","object","apdu","asdu","cpf"]:
            if k in text.lower(): fields.append(k)
        return fields[:10]

    def _infer_poc(self, text: str):
        return "Use a minimized crashing input/artifact and replay it against the same target binary under GDB or sanitizer instrumentation."
