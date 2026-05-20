from __future__ import annotations

import hashlib
import re


class VulnerabilityClassifier:
    def classify(self, protocol: str, gdb_context: dict, artifact_path: str | None = None, artifact_id: str | None = None):
        text = "\n".join(str(gdb_context.get(k, "")) for k in ["signal", "backtrace", "frame_locals", "stdout_stderr_tail", "disassembly"]).lower()
        coarse = "unknown"
        vuln = "unknown"
        cwe = ""
        error_type = "unknown-crash"
        if "sigsegv" in text and any(x in text for x in ["memcpy", "strcpy", "buffer", "overflow"]):
            coarse = "memory-corruption"; vuln = "buffer-overflow"; cwe = "CWE-120"; error_type = "segmentation-fault / possible buffer overflow"
        elif "sigsegv" in text:
            coarse = "bounds-check"; vuln = "out-of-bounds-access"; cwe = "CWE-125"; error_type = "segmentation-fault / out-of-bounds access"
        elif "null" in text:
            coarse = "null-deref"; vuln = "null-pointer-dereference"; cwe = "CWE-476"; error_type = "null pointer dereference"
        elif "use-after-free" in text or "uaf" in text:
            coarse = "use-after-free"; vuln = "use-after-free"; cwe = "CWE-416"; error_type = "use-after-free"
        elif "integer" in text:
            coarse = "integer-issue"; vuln = "integer-overflow"; cwe = "CWE-190"; error_type = "integer overflow or underflow"
        elif "timeout" in text or "hang" in text:
            coarse = "resource-exhaustion"; vuln = "denial-of-service"; cwe = "CWE-400"; error_type = "hang or resource exhaustion"
        elif any(x in text for x in ["parse", "decode", "packet", "frame"]):
            coarse = "parser-state"; vuln = "parser-state-bug"; cwe = ""; error_type = "parser state error"

        loc = gdb_context.get("source_location") or {}
        bt = gdb_context.get("backtrace", "")
        sig_src = (bt or gdb_context.get("stdout_stderr_tail", ""))[:2000]
        sig = hashlib.sha256(sig_src.encode(errors="ignore")).hexdigest()[:16]
        function = gdb_context.get("function_name") or ""
        if not function:
            m = re.search(r"#0\s+(?:0x[0-9a-fA-F]+\s+in\s+)?([A-Za-z_][A-Za-z0-9_:~.]*)\s*\(", bt)
            if m:
                function = m.group(1)

        possible_exploit = self._exploitability(coarse)
        line = loc.get("line")
        return {
            "vuln_type": vuln,
            "coarse_type": coarse,
            "cwe": cwe,
            "error_type": error_type,
            "root_cause": self._root(coarse),
            "direct_cause": gdb_context.get("signal") or "crash or abnormal termination",
            "crash_signature": sig,
            "file": loc.get("file", ""),
            "function": function,
            "line": line,
            "line_range": {"start": max(1, int(line) - 5), "end": int(line) + 5} if isinstance(line, int) else {},
            "stack_summary": (bt[:1200] if bt else gdb_context.get("stdout_stderr_tail", "")[:1200]),
            "repro_steps": [
                "Build the target with debug symbols and sanitizer flags when possible.",
                "Replay the stored artifact against the same target binary and arguments.",
                "Run the generated debug session under GDB to confirm the same crash signature.",
            ],
            "poc_concept": "The proof-of-concept input is the archived crash seed. Use it only for controlled reproduction and validation.",
            "possible_exploitability": possible_exploit,
            "potential_exploitation_description": possible_exploit,
            "fix_suggestion": "Validate protocol length/count/state fields before memory access and add regression tests using the stored artifact.",
            "confidence": 0.68 if coarse != "unknown" else 0.35,
            "artifact_id": artifact_id,
            "artifact_path": artifact_path,
        }

    def _root(self, coarse):
        return {
            "memory-corruption": "Unsafe memory operation reached by malformed protocol data.",
            "bounds-check": "Parser uses untrusted length/count without sufficient bounds checks.",
            "null-deref": "Error path or optional object is dereferenced without validation.",
            "use-after-free": "Object lifetime is not guarded across parser/session state transitions.",
            "integer-issue": "Arithmetic on untrusted size/count can overflow or underflow.",
            "resource-exhaustion": "Input can force excessive CPU, memory, or loop behavior.",
            "parser-state": "Protocol parser accepts invalid message shape or state transition.",
        }.get(coarse, "Insufficient evidence; manual review required.")

    def _exploitability(self, coarse):
        return {
            "memory-corruption": "May be exploitable for process crash, memory disclosure, or control-flow impact depending on allocator state and mitigations; this report does not generate a weaponized exploit.",
            "bounds-check": "May allow denial of service or out-of-bounds read/write if attacker-controlled length fields reach memory access.",
            "null-deref": "Most likely denial of service through process crash; exploitation beyond DoS is unlikely without additional primitives.",
            "use-after-free": "Potentially high impact if freed object contents can be attacker-influenced; confirm with ASAN and heap tracing.",
            "integer-issue": "May become memory corruption if overflowed sizes feed allocation, copy, or bounds logic.",
            "resource-exhaustion": "Likely denial of service via CPU, memory, or infinite wait behavior.",
            "parser-state": "May cause parser desynchronization, bypass, or denial of service depending on protocol state handling.",
        }.get(coarse, "Exploitability is unknown; manual triage is required.")
