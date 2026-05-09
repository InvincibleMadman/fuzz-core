from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


GENERATED_DIR_MARKER = '.fuzz_core_generated'
GENERATED_DIR_NAMES = {
    'workspace',
    'seeds',
    'risk_results',
    'instrumented',
    'protocol_specs',
    'uploads',
    '.fuzz_core_generated',
}
SOURCE_FILE_SUFFIXES = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.py', '.js', '.ts', '.java', '.rs'}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def mark_generated_dir(path: Path, kind: str | None = None) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    marker = path / GENERATED_DIR_MARKER
    if not marker.exists():
        marker.write_text(kind or 'generated', encoding='utf-8')
    return path


def is_generated_dir(path: Path) -> bool:
    try:
        return (path / GENERATED_DIR_MARKER).exists() or path.name in GENERATED_DIR_NAMES
    except Exception:
        return False


def resolve_path(path: str | os.PathLike[str], base: str | os.PathLike[str] | None = None) -> Path:
    p = Path(path).expanduser()
    if p.is_absolute():
        return p.resolve()
    if base is None:
        return p.resolve()
    return (Path(base) / p).resolve()


def latest_file(directory: Path, pattern: str = "*.json") -> Path | None:
    if not directory.exists():
        return None
    matches = list(directory.glob(pattern))
    if not matches:
        return None
    return max(matches, key=lambda p: p.stat().st_mtime)


def write_json(path: Path, payload: dict) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def append_jsonl(path: Path, payload: dict) -> None:
    ensure_parent(path)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def tail_lines(path: Path, limit: int = 100) -> list[str]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    return [line.rstrip("\n") for line in lines[-limit:]]


def parse_fuzzer_stats(path: Path) -> dict[str, str]:
    stats: dict[str, str] = {}
    if not path.exists():
        return stats
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    return stats


def extract_numeric_value(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if value is None:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", str(value))
    if not match:
        return None
    try:
        return float(match.group(0))
    except Exception:
        return None


def guess_stats_file(output_dir: Path) -> Path | None:
    direct = output_dir / "fuzzer_stats"
    if direct.exists():
        return direct
    candidates = []
    if output_dir.exists():
        for child in output_dir.iterdir():
            cand = child / "fuzzer_stats"
            if cand.exists():
                candidates.append(cand)
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def copy_file(src: Path, dst: Path) -> Path:
    ensure_parent(dst)
    shutil.copy2(src, dst)
    return dst


def write_text(path: Path, text: str) -> None:
    ensure_parent(path)
    path.write_text(text, encoding="utf-8")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def init_history_db(path: Path) -> None:
    ensure_parent(path)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS coverage_history (
                ts TEXT NOT NULL,
                cycles_done INTEGER,
                execs_done INTEGER,
                pending_total INTEGER,
                unique_crashes INTEGER,
                unique_hangs INTEGER,
                bitmap_cvg REAL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def append_history_db(path: Path, snapshot: dict) -> None:
    init_history_db(path)
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "INSERT INTO coverage_history (ts, cycles_done, execs_done, pending_total, unique_crashes, unique_hangs, bitmap_cvg) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                snapshot.get("timestamp"),
                int(snapshot.get("cycles_done") or 0),
                int(snapshot.get("execs_done") or 0),
                int(snapshot.get("pending_total") or 0),
                int(snapshot.get("unique_crashes") or 0),
                int(snapshot.get("unique_hangs") or 0),
                float(snapshot.get("bitmap_cvg") or 0.0),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def read_history_db(path: Path, limit: int = 200) -> list[dict]:
    if not path.exists():
        return []
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT ts, cycles_done, execs_done, pending_total, unique_crashes, unique_hangs, bitmap_cvg FROM coverage_history ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    rows = list(reversed(rows))
    return [dict(row) for row in rows]


def iter_source_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        if root.suffix.lower() in SOURCE_FILE_SUFFIXES:
            yield root
        return

    def _walk(directory: Path) -> Iterator[Path]:
        if is_generated_dir(directory):
            return
        for path in directory.iterdir():
            if path.is_dir():
                yield from _walk(path)
                continue
            if path.suffix.lower() in SOURCE_FILE_SUFFIXES:
                yield path

    if root.exists() and root.is_dir():
        yield from _walk(root)


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)
