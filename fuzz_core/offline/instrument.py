from __future__ import annotations

import shutil
from pathlib import Path

from ..config import ConfigStore
from ..offline.risk import RiskAnalysisService
from ..utils.fs import ensure_dir, mark_generated_dir, read_json, utc_now_iso


class InstrumentationService:
    def __init__(self, config_store: ConfigStore, risk_service: RiskAnalysisService) -> None:
        self.config_store = config_store
        self.risk_service = risk_service

    def _resolve_analysis(self, analysis_path: str | None) -> Path:
        if analysis_path:
            path = Path(analysis_path).expanduser().resolve()
            if not path.exists():
                raise FileNotFoundError(f'analysis path not found: {path}')
            return path
        latest = self.risk_service.latest()
        if latest is None:
            raise FileNotFoundError('no risk analysis file available')
        return latest

    def instrument(
        self,
        source_path: str | None = None,
        analysis_path: str | None = None,
        output_path: str | None = None,
        in_place: bool = False,
    ) -> dict:
        analysis_file = self._resolve_analysis(analysis_path)
        analysis = read_json(analysis_file)
        findings = analysis.get('findings', [])
        if not findings:
            return {
                'analysis_path': str(analysis_file),
                'instrumented_files': [],
                'inserted_markers': 0,
                'generated_at': utc_now_iso(),
            }

        source_root = Path(source_path).expanduser().resolve() if source_path else None
        if source_root is not None and not source_root.exists():
            raise FileNotFoundError(f'source path not found: {source_root}')

        grouped: dict[Path, list[dict]] = {}
        for item in findings:
            path = Path(item.get('file', '')).expanduser().resolve()
            if source_root is not None:
                if source_root.is_file() and path != source_root:
                    continue
                if source_root.is_dir():
                    try:
                        path.relative_to(source_root)
                    except Exception:
                        continue
            grouped.setdefault(path, []).append(item)

        if not grouped:
            raise FileNotFoundError('no analysis findings matched the requested source path')

        resolved_output = Path(output_path).expanduser().resolve() if output_path else None
        if source_root is not None and source_root.is_dir() and resolved_output is not None:
            self._prepare_directory_output(source_root, resolved_output)

        instrumented_files: list[str] = []
        inserted_markers = 0
        for file_path, items in grouped.items():
            if not file_path.exists() or not file_path.is_file():
                continue
            target = self._target_path(file_path, source_root, resolved_output, in_place)
            target.parent.mkdir(parents=True, exist_ok=True)
            text_lines = file_path.read_text(encoding='utf-8', errors='replace').splitlines()
            inserts: dict[int, list[str]] = {}
            for index, item in enumerate(sorted(items, key=lambda v: int(v.get('line') or 1)), start=1):
                line_no = int(item.get('line') or 1)
                severity = str(item.get('severity', 'medium'))
                sev_level = int(item.get('severity_level') or 0)
                pattern = str(item.get('pattern', 'unknown')).replace('"', "'")
                marker = f'__POLAR_INS(({sev_level}, {index}, "{severity}", "{pattern}"));'
                inserts.setdefault(line_no, []).append(marker)
                inserted_markers += 1

            new_lines: list[str] = []
            for line_no, line in enumerate(text_lines, start=1):
                for marker in inserts.get(line_no, []):
                    new_lines.append(marker)
                new_lines.append(line)
            target.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
            instrumented_files.append(str(target))

        return {
            'instrumented_files': instrumented_files,
            'analysis_path': str(analysis_file),
            'inserted_markers': inserted_markers,
            'generated_at': utc_now_iso(),
            'in_place': self._effective_in_place(resolved_output, in_place),
            'copied_source_tree': bool(source_root is not None and source_root.is_dir() and resolved_output is not None),
            'output_path': str(resolved_output) if resolved_output is not None else (str(source_root) if source_root is not None else None),
        }

    def _effective_in_place(self, output_path: Path | None, in_place: bool) -> bool:
        if in_place:
            return True
        return output_path is None

    def _prepare_directory_output(self, source_root: Path, output_root: Path) -> None:
        output_root.mkdir(parents=True, exist_ok=True)
        mark_generated_dir(output_root, 'instrumented-output')
        for item in source_root.iterdir():
            destination = output_root / item.name
            if item.is_dir():
                shutil.copytree(item, destination, dirs_exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, destination)

    def _target_path(self, src: Path, source_root: Path | None, output_path: Path | None, in_place: bool) -> Path:
        # New rule: when output_path is omitted, instrument in place by default.
        if in_place or output_path is None:
            return src

        out = output_path
        if source_root is not None and source_root.is_dir():
            try:
                rel = src.relative_to(source_root)
                return out / rel
            except Exception:
                return out / src.name

        if out.suffix:
            return out
        return out / src.name

    def save_uploaded_analysis(self, filename: str, content: bytes) -> dict:
        cfg = self.config_store.get()
        upload_dir = mark_generated_dir(ensure_dir(Path(cfg.legacy_paths.risk_upload_dir)), 'risk-upload')
        risk_dir = mark_generated_dir(ensure_dir(Path(cfg.legacy_paths.risk_output_dir)), 'risk-output')
        canonical_name = cfg.offline.default_risk_filename
        upload_target = upload_dir / canonical_name
        upload_target.write_bytes(content)
        risk_target = risk_dir / canonical_name
        if risk_target.resolve() != upload_target.resolve():
            risk_target.write_bytes(content)
        return {'saved_path': str(upload_target), 'mirrored_to': str(risk_target), 'size': len(content)}
