from __future__ import annotations

from pathlib import Path


def txt_to_bin(src_dir: str, dst_dir: str):
    src = Path(src_dir)
    dst = Path(dst_dir)
    dst.mkdir(parents=True, exist_ok=True)
    for txt in src.glob('*.txt'):
        (dst / f'{txt.stem}.bin').write_bytes(txt.read_text(encoding='utf-8', errors='replace').encode('utf-8'))
