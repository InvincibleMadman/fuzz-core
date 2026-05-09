from __future__ import annotations

import os
from pathlib import Path


def get_txt_files(directory: str):
    txt_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.txt'):
                txt_files.append(Path(file).stem)
    return txt_files


def clear_txt_files(directory: str):
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            os.remove(os.path.join(directory, filename))
