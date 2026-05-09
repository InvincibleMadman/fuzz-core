from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..config import ConfigStore
from ..utils.fs import ensure_dir, latest_file, mark_generated_dir, read_json, sanitize_filename, utc_now_iso


class SeedGenerationService:
    def __init__(self, config_store: ConfigStore) -> None:
        self.config_store = config_store

    def _default_output_dir(self) -> Path:
        cfg = self.config_store.get()
        return mark_generated_dir(ensure_dir(Path(cfg.legacy_paths.init_seed_txt_dir)), 'seed-output')

    def _default_bin_dir(self) -> Path:
        cfg = self.config_store.get()
        return mark_generated_dir(ensure_dir(Path(cfg.legacy_paths.bin_seed_dir)), 'seed-bin-output')

    def _latest_spec(self, spec_dir: str | None = None) -> Path:
        cfg = self.config_store.get()
        directory = Path(spec_dir or cfg.paths.protocol_scan_dir)
        latest = latest_file(directory, '*.json')
        if latest is None:
            latest = latest_file(Path(cfg.legacy_paths.protocol_output_dir), '*.json')
        if latest is None:
            raise FileNotFoundError('no protocol spec json found')
        return latest

    def _issue_doc_candidates(self, issue_doc_dir: str | None, include_uploaded_vuldocs: bool) -> list[Path]:
        cfg = self.config_store.get()
        candidates: list[Path] = []
        roots: list[Path] = []
        if issue_doc_dir:
            roots.append(Path(issue_doc_dir))
        roots.append(Path(cfg.legacy_paths.distill_dir))
        roots.append(Path(cfg.legacy_paths.init_seed_txt_dir))
        if include_uploaded_vuldocs:
            roots.append(Path(cfg.legacy_paths.vuldoc_upload_dir))
        for root in roots:
            if not root.exists():
                continue
            for pattern in ('*.txt', '*.json', '*.md'):
                candidates.extend(sorted(root.glob(pattern)))
        unique: list[Path] = []
        seen: set[str] = set()
        for path in candidates:
            resolved = str(path.resolve())
            if resolved in seen or not path.is_file():
                continue
            seen.add(resolved)
            unique.append(path.resolve())
        return unique

    def generate(
        self,
        spec_path: str | None = None,
        spec_dir: str | None = None,
        output_dir: str | None = None,
        count: int | None = None,
        binary: bool = True,
        issue_doc_dir: str | None = None,
        use_uploaded_vuldocs: bool = False,
    ) -> dict:
        cfg = self.config_store.get()
        out_dir = mark_generated_dir(ensure_dir(Path(output_dir).expanduser().resolve()), 'seed-output') if output_dir else self._default_output_dir()
        bin_dir = self._default_bin_dir() if binary else None
        count = count or cfg.offline.default_seed_count

        spec_used = None
        issue_docs: list[str] = []
        created_text: list[str] = []
        created_bin: list[str] = []
        mode = 'spec'

        try:
            spec_file = Path(spec_path).expanduser().resolve() if spec_path else self._latest_spec(spec_dir)
            spec_used = str(spec_file)
            payload = read_json(spec_file)
            templates = payload.get('seed_templates') or []
            if not templates:
                templates = [{'name': 'fallback', 'format': ['HDR', 'LEN', 'PAYLOAD', 'CRC']}]
            for idx in range(count):
                tpl = templates[idx % len(templates)]
                parts = tpl.get('format') or ['HDR', 'PAYLOAD']
                line = '|'.join(str(part) for part in parts)
                txt_path = out_dir / f'seed_{idx:03d}.txt'
                txt_path.write_text(line + '\n', encoding='utf-8')
                created_text.append(str(txt_path))
                if binary and bin_dir is not None:
                    bin_path = bin_dir / f'seed_{idx:03d}.bin'
                    bin_path.write_bytes(line.encode('utf-8', errors='ignore'))
                    created_bin.append(str(bin_path))
        except FileNotFoundError:
            mode = 'issue_docs'
            docs = self._issue_doc_candidates(issue_doc_dir, use_uploaded_vuldocs)
            if not docs:
                raise FileNotFoundError('no protocol spec found and no uploaded VulDoc/queue text available')
            for idx, path in enumerate(docs[:count]):
                issue_docs.append(str(path))
                content = path.read_text(encoding='utf-8', errors='replace').strip()
                seed_body = self._doc_to_seed_line(path, content, idx)
                txt_path = out_dir / f'{sanitize_filename(path.stem)}_{idx:03d}.txt'
                txt_path.write_text(seed_body + '\n', encoding='utf-8')
                created_text.append(str(txt_path))
                if binary and bin_dir is not None:
                    bin_path = bin_dir / f'{sanitize_filename(path.stem)}_{idx:03d}.bin'
                    bin_path.write_bytes(seed_body.encode('utf-8', errors='ignore'))
                    created_bin.append(str(bin_path))

        manifest = {
            'generated_at': utc_now_iso(),
            'mode': mode,
            'spec_path': spec_used,
            'issue_docs': issue_docs,
            'text_output_dir': str(out_dir),
            'bin_output_dir': str(bin_dir) if bin_dir is not None else None,
            'count': len(created_text),
            'binary': binary,
            'text_files': created_text,
            'bin_files': created_bin,
            'bin_hex': self._read_bin_hex(created_bin),
        }
        (out_dir / 'seed_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
        return manifest

    @staticmethod
    def _doc_to_seed_line(path: Path, content: str, idx: int) -> str:
        text = ' '.join(content.split())[:240]
        if path.suffix.lower() == '.json':
            try:
                obj = json.loads(content)
                text = json.dumps(obj, ensure_ascii=False)[:240]
            except Exception:
                pass
        return f'DOC={path.stem}|IDX={idx}|BODY={text}'

    @staticmethod
    def _read_bin_hex(paths: Iterable[str]) -> dict[str, str]:
        data: dict[str, str] = {}
        for item in paths:
            path = Path(item)
            if path.exists():
                data[path.name] = path.read_bytes().hex()
        return data
