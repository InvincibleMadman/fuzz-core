from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import TargetConfig


class GDBDriver:
    def __init__(self, gdb_path: str = "gdb", timeout_sec: int = 20):
        self.gdb_path = gdb_path
        self.timeout_sec = timeout_sec

    def collect(self, target: TargetConfig, artifact_path: str | None = None):
        binary = target.binary_path
        if not binary or not Path(binary).exists() or not shutil.which(self.gdb_path):
            return self._synthetic_context(target, artifact_path, reason="missing binary or gdb")

        cmd_file = Path(tempfile.mkdtemp()) / "gdb.cmd"
        commands = [
            "set pagination off",
            "set confirm off",
            "handle SIGPIPE nostop noprint pass",
            "run",
            "echo \\n---SIGNAL---\\n",
            "info program",
            "echo \\n---BACKTRACE---\\n",
            "bt full",
            "echo \\n---THREADS---\\n",
            "info threads",
            "echo \\n---REGISTERS---\\n",
            "info registers",
            "echo \\n---FRAME---\\n",
            "frame",
            "info locals",
            "echo \\n---DISASM---\\n",
            "x/16i $pc",
            "quit",
        ]
        cmd_file.write_text("\n".join(commands) + "\n", encoding="utf-8")

        argv = [self.gdb_path, "-q", "--batch", "-x", str(cmd_file), "--args", binary, *self._target_args(target, artifact_path)]
        stdin_data = None
        if target.transport_type == "stdin" and artifact_path and Path(artifact_path).exists():
            stdin_data = Path(artifact_path).read_bytes()

        env = os.environ.copy()
        env.update(target.env or {})
        try:
            cp = subprocess.run(
                argv,
                cwd=target.cwd or None,
                env=env,
                input=stdin_data,
                capture_output=True,
                timeout=self.timeout_sec,
            )
            out = (cp.stdout + cp.stderr).decode(errors="ignore")
            return self._parse(out, cp.returncode, target, artifact_path, argv)
        except Exception as e:
            return self._synthetic_context(target, artifact_path, reason=f"gdb failed: {e}")

    def _target_args(self, target: TargetConfig, artifact_path: str | None) -> list[str]:
        args = list(target.args or [])
        if target.transport_type == "file" and artifact_path:
            if "@@" in args:
                args = [artifact_path if a == "@@" else a.replace("@@", artifact_path) for a in args]
            else:
                args.append(artifact_path)
        return args

    def _parse(self, text: str, rc: int, target: TargetConfig, artifact_path: str | None, argv: list[str]):
        bt = self._section(text, "---BACKTRACE---", "---THREADS---")
        loc = self._source_location(text)
        fn = self._function_name(bt)
        return {
            "exit_code": rc,
            "signal": self._find_signal(text),
            "backtrace": bt,
            "threads": self._section(text, "---THREADS---", "---REGISTERS---"),
            "registers": self._section(text, "---REGISTERS---", "---FRAME---"),
            "frame_locals": self._section(text, "---FRAME---", "---DISASM---"),
            "disassembly": self._section(text, "---DISASM---", None),
            "stdout_stderr_tail": text[-4000:],
            "source_location": loc,
            "function_name": fn,
            "target_argv": [shlex.quote(x) for x in argv],
            "artifact_path": artifact_path,
        }

    def _section(self, text, start, end):
        if start not in text:
            return ""
        part = text.split(start, 1)[1]
        if end and end in part:
            part = part.split(end, 1)[0]
        return part.strip()[:12000]

    def _find_signal(self, text):
        for sig in ["SIGSEGV", "SIGABRT", "SIGFPE", "SIGBUS", "SIGILL"]:
            if sig in text:
                return sig
        if "exited normally" in text.lower():
            return ""
        return ""

    def _source_location(self, text):
        m = re.search(r"at ([^:\n]+):(\d+)", text)
        return {"file": m.group(1), "line": int(m.group(2))} if m else {}

    def _function_name(self, backtrace: str):
        m = re.search(r"#0\s+(?:0x[0-9a-fA-F]+\s+in\s+)?([A-Za-z_][A-Za-z0-9_:~.]*)\s*\(", backtrace)
        return m.group(1) if m else ""

    def _synthetic_context(self, target, artifact_path, reason):
        artifact_bytes = Path(artifact_path).read_bytes() if artifact_path and Path(artifact_path).exists() else b""
        return {
            "exit_code": None,
            "signal": "",
            "backtrace": "",
            "threads": "",
            "frame_locals": "",
            "registers": "",
            "source_location": {},
            "function_name": "",
            "disassembly": "",
            "stdout_stderr_tail": reason,
            "artifact_size": len(artifact_bytes),
            "artifact_path": artifact_path,
        }
