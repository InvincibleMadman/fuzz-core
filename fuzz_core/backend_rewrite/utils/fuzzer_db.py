from __future__ import annotations

from pathlib import Path
from threading import Event
from time import sleep

from ...utils.fs import append_history_db, guess_stats_file, parse_fuzzer_stats, utc_now_iso


def save_fuzzer_stats_loop(db_path: str, stats_file_path: str, stop_event: Event | None = None, interval: int = 5):
    stop_event = stop_event or Event()
    stats_path = Path(stats_file_path)
    while not stop_event.is_set():
        path = stats_path if stats_path.exists() else guess_stats_file(stats_path.parent)
        if path is not None and path.exists():
            stats = parse_fuzzer_stats(path)
            append_history_db(Path(db_path), {
                'timestamp': utc_now_iso(),
                'cycles_done': int(float(stats.get('cycles_done', '0') or 0)),
                'execs_done': int(float(stats.get('execs_done', '0') or 0)),
                'pending_total': int(float(stats.get('pending_total', '0') or 0)),
                'unique_crashes': int(float(stats.get('unique_crashes', '0') or 0)),
                'unique_hangs': int(float(stats.get('unique_hangs', '0') or 0)),
                'bitmap_cvg': float(str(stats.get('bitmap_cvg', '0')).strip('%') or 0),
            })
        sleep(interval)
