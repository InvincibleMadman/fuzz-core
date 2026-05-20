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

    def collect(
        self,
        target: TargetConfig,
        artifact_path: str | None = None,
        log_callback=None,
    ):
        binary = target.binary_path
        if not binary or not Path(binary).exists() or not shutil.which(self.gdb_path):
            reason = "missing binary or gdb"
            if log_callback:
                log_callback("gdb_skipped", reason, {"binary": binary, "gdb_path": self.gdb_path}, "warning")
            return self._synthetic_context(target, artifact_path, reason=reason)

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

        argv = [
            self.gdb_path,
            "-q",
            "--batch",
            "-x",
            str(cmd_file),
            "--args",
            binary,
            *self._target_args(target, artifact_path),
        ]

        stdin_data = None
        if target.transport_type == "stdin" and artifact_path and Path(artifact_path).exists():
            stdin_data = Path(artifact_path).read_bytes()

        env = os.environ.copy()
        env.update(target.env or {})

        if log_callback:
            log_callback(
                "gdb_launch",
                "Launching GDB",
                {
                    "argv": argv,
                    "cwd": target.cwd,
                    "artifact_path": artifact_path,
                    "transport_type": target.transport_type,
                },
            )

        try:
            proc = subprocess.Popen(
                argv,
                cwd=target.cwd or None,
                env=env,
                stdin=subprocess.PIPE if stdin_data is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
            )

            if stdin_data is not None and proc.stdin:
                proc.stdin.write(stdin_data)
                proc.stdin.close()
                if log_callback:
                    log_callback(
                        "gdb_stdin",
                        "Crash seed bytes written to target stdin",
                        {"bytes": len(stdin_data)},
                    )

            stdout_chunks: list[bytes] = []
            stderr_chunks: list[bytes] = []

            import threading

            stdout_thread = threading.Thread(
                target=self._read_stream,
                args=(proc.stdout, stdout_chunks, "stdout", log_callback),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=self._read_stream,
                args=(proc.stderr, stderr_chunks, "stderr", log_callback),
                daemon=True,
            )

            stdout_thread.start()
            stderr_thread.start()

            try:
                proc.wait(timeout=self.timeout_sec)
            except subprocess.TimeoutExpired:
                proc.kill()
                if log_callback:
                    log_callback(
                        "gdb_timeout",
                        f"GDB timed out after {self.timeout_sec}s",
                        {"timeout_sec": self.timeout_sec},
                        "error",
                    )

            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

            out = (b"".join(stdout_chunks) + b"".join(stderr_chunks)).decode(errors="ignore")

            if log_callback:
                log_callback(
                    "gdb_exit",
                    "GDB process exited",
                    {"returncode": proc.returncode},
                )

            return self._parse(out, proc.returncode, target, artifact_path, argv)

        except Exception as e:
            if log_callback:
                log_callback(
                    "gdb_failed",
                    f"GDB execution failed: {e}",
                    {"error": str(e)},
                    "error",
                )
            return self._synthetic_context(target, artifact_path, reason=f"gdb failed: {e}")


def _read_stream(self, stream, chunks: list[bytes], name: str, log_callback=None) -> None:
    if not stream:
        return

    while True:
        line = stream.readline()
        if not line:
            break

        chunks.append(line)

        if log_callback:
            text = line.decode(errors="ignore").rstrip()
            if text:
                log_callback(
                    f"gdb_{name}",
                    text,
                    {"stream": name},
                )

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
