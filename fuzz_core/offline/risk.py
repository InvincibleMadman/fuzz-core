from __future__ import annotations

import json
from pathlib import Path

from ..config import ConfigStore
from ..utils.fs import copy_file, ensure_dir, iter_source_files, latest_file, mark_generated_dir, read_json, utc_now_iso, write_json


RISK_RULES = [
    (3, 'critical', ['strcpy', 'strcat', 'gets', 'system(', 'popen(', 'eval(']),
    (2, 'high', ['memcpy', 'memmove', 'recv(', 'read(', 'write(', 'socket(', 'send(']),
    (1, 'medium', ['malloc(', 'calloc(', 'realloc(', 'free(', 'assert(', 'atoi(', 'sscanf(']),
    (0, 'low', ['for (', 'while (', 'switch (', 'goto ']),
]


class RiskAnalysisService:
    def __init__(self, config_store: ConfigStore) -> None:
        self.config_store = config_store

    def _default_output_path(self) -> Path:
        cfg = self.config_store.get()
        return mark_generated_dir(ensure_dir(Path(cfg.legacy_paths.risk_output_dir)), 'risk-output') / cfg.offline.default_risk_filename

    def analyze(self, source_path: str, output_path: str | None = None, copy_to_scan_dir: bool = False, **options) -> dict:
        source_root = Path(source_path).expanduser().resolve()
        if not source_root.exists():
            raise FileNotFoundError(f'source path not found: {source_root}')

        findings = []
        for file_path in iter_source_files(source_root):
            text = file_path.read_text(encoding='utf-8', errors='replace').splitlines()
            for lineno, line in enumerate(text, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                for level, severity, needles in RISK_RULES:
                    hit = next((needle for needle in needles if needle in stripped), None)
                    if not hit:
                        continue
                    findings.append(
                        {
                            'id': f'{file_path.name}:{lineno}:{hit}',
                            'file': str(file_path),
                            'line': lineno,
                            'severity_level': level,
                            'severity': severity,
                            'confidence_score': level + 1,
                            'pattern': hit,
                            'code': stripped,
                            'reason': f'matched heuristic risk pattern: {hit}',
                        }
                    )
                    break

        summary = {
            'schema_version': 'backend-rewrite.v1',
            'generated_at': utc_now_iso(),
            'source_path': str(source_root),
            'options': options,
            'confidence_score': max((item['confidence_score'] for item in findings), default=0),
            'vulnerability_types': sorted({item['severity'] for item in findings}),
            'total_findings': len(findings),
            'severity_count': {
                'critical': sum(1 for item in findings if item['severity'] == 'critical'),
                'high': sum(1 for item in findings if item['severity'] == 'high'),
                'medium': sum(1 for item in findings if item['severity'] == 'medium'),
                'low': sum(1 for item in findings if item['severity'] == 'low'),
            },
            'findings': findings,
        }

        out = Path(output_path).expanduser().resolve() if output_path else self._default_output_path()
        if out.is_dir() or out.suffix == '':
            out = ensure_dir(out) / self.config_store.get().offline.default_risk_filename
        write_json(out, summary)

        copied_to = None
        if copy_to_scan_dir:
            cfg = self.config_store.get()
            scan_dir = mark_generated_dir(ensure_dir(Path(cfg.paths.risk_scan_dir)), 'risk-scan')
            copied = scan_dir / out.name
            if copied.resolve() != out.resolve():
                copy_file(out, copied)
                copied_to = str(copied)

        return {'output_path': str(out), 'copied_to': copied_to, 'analysis': summary}

    def preview(self, analysis_path: str | None = None) -> dict:
        cfg = self.config_store.get()
        if analysis_path:
            path = Path(analysis_path).expanduser().resolve()
        else:
            path = self.latest() or (Path(cfg.legacy_paths.risk_output_dir) / cfg.offline.default_risk_filename)
        if not path.exists():
            return {'status': 'waiting', 'preview': '', 'size': 0, 'analysis_path': str(path)}
        text = path.read_text(encoding='utf-8', errors='ignore')
        limit = cfg.offline.risk_preview_chars
        preview = text[-limit:] if len(text) > limit else text
        return {'status': 'updating', 'preview': preview, 'size': len(text), 'analysis_path': str(path)}

    def latest(self, directory: str | None = None) -> Path | None:
        cfg = self.config_store.get()
        scan_dir = Path(directory or cfg.paths.risk_scan_dir)
        latest = latest_file(scan_dir, '*.json')
        if latest is not None:
            return latest
        fallback = Path(cfg.legacy_paths.risk_output_dir)
        return latest_file(fallback, '*.json')

    def read_analysis(self, analysis_path: str | None = None) -> dict:
        path = Path(analysis_path).expanduser().resolve() if analysis_path else self.latest()
        if path is None or not path.exists():
            raise FileNotFoundError('analysis path not found')
        return read_json(path)
