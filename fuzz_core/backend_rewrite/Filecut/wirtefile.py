from __future__ import annotations

import os


def vul_write_to_file(filename: str, response: str, directory: str):
    file_path = os.path.join(directory, filename + '.txt')
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(response)
