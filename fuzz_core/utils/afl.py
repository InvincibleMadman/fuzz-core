from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from ..config import AppConfig


def _candidate_paths(cfg: AppConfig) -> list[str]:
    candidates: list[str] = []
    explicit = cfg.afl.afl_binary
    if explicit:
        candidates.append(explicit)
    candidates.extend(cfg.afl.binary_search_paths)
    seen: set[str] = set()
    ordered: list[str] = []
    for item in candidates:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def resolve_binary(name_or_path: str) -> str | None:
    expanded = os.path.expanduser(name_or_path)
    if os.path.isabs(expanded) or os.path.sep in expanded:
        path = Path(expanded)
        if path.exists() and os.access(path, os.X_OK):
            return str(path.resolve())
        return None
    found = shutil.which(expanded)
    return found


def resolve_afl_binary(cfg: AppConfig, override: str | None = None) -> str:
    if override:
        resolved = resolve_binary(override)
        if resolved:
            return resolved
        raise FileNotFoundError(f'AFL binary not found: {override}')

    errors: list[str] = []
    for item in _candidate_paths(cfg):
        resolved = resolve_binary(item)
        if resolved:
            return resolved
        errors.append(item)
    searched = ', '.join(errors) if errors else '<none>'
    raise FileNotFoundError(f'AFL binary not found. searched: {searched}. Put afl-fuzz in PATH or configure afl.afl_binary / afl.binary_search_paths')


def resolve_afl_tools(cfg: AppConfig) -> dict[str, str | None]:
    result: dict[str, str | None] = {'afl-fuzz': None}
    try:
        result['afl-fuzz'] = resolve_afl_binary(cfg)
    except FileNotFoundError:
        result['afl-fuzz'] = None
    for tool in cfg.afl.compiler_binaries:
        result[tool] = resolve_binary(tool)
    return result


def runtime_dirs(payload: dict[str, Any]) -> dict[str, str | None]:
    def first(*keys: str) -> str | None:
        for key in keys:
            value = payload.get(key)
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return None

    return {
        'run_cwd': first('runCwd', 'run_cwd', 'cwd'),
        'source_dir': first('sourceDir', 'source_dir'),
        'build_dir': first('buildDir', 'build_dir'),
    }
