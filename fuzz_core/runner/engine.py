from __future__ import annotations

import os
import subprocess
import threading
from pathlib import Path

from .models import AFLConfigModel


class ExecEngine:
    def __init__(self, afl: AFLConfigModel, log_path: Path) -> None:
        self.afl = afl
        self.log_path = log_path
        self.processes: list[subprocess.Popen] = []
        self._lock = threading.RLock()

    def _worker_cmd(self, idx: int) -> list[str]:
        cmd = [self.afl.afl_binary, '-i', self.afl.input_dir, '-o', self.afl.output_dir]
        if self.afl.workers > 1:
            if idx == 0:
                cmd.extend(['-M', 'runner-main'])
            else:
                cmd.extend(['-S', f'runner-{idx}'])
        cmd.extend(self.afl.fuzzer_args)
        cmd.append('--')
        cmd.append(self.afl.target_binary)
        cmd.extend(self.afl.target_args)
        return cmd

    def _resolve_cwd(self) -> Path:
        for candidate in (self.afl.run_cwd, self.afl.build_dir, self.afl.source_dir):
            if candidate:
                path = Path(candidate).expanduser().resolve()
                if path.exists() and path.is_dir():
                    return path
        target_parent = Path(self.afl.target_binary).expanduser().resolve().parent
        if target_parent.exists() and target_parent.is_dir():
            return target_parent
        return Path(self.afl.output_dir).expanduser().resolve()

    def start(self) -> list[int]:
        Path(self.afl.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.afl.input_dir).mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        run_cwd = self._resolve_cwd()
        with self._lock, self.log_path.open('ab') as log_file:
            for idx in range(max(1, self.afl.workers)):
                cmd = self._worker_cmd(idx)
                env = os.environ.copy()
                env.update(self.afl.env)
                proc = subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    env=env,
                    cwd=str(run_cwd),
                )
                self.processes.append(proc)
        return [proc.pid for proc in self.processes]

    def stop(self) -> None:
        with self._lock:
            for proc in self.processes:
                if proc.poll() is None:
                    proc.terminate()
            for proc in self.processes:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def is_running(self) -> bool:
        with self._lock:
            return any(proc.poll() is None for proc in self.processes)

    def return_codes(self) -> list[int | None]:
        with self._lock:
            return [proc.poll() for proc in self.processes]
