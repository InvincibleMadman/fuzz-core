from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..config import ConfigStore
from ..utils.fs import copy_file, ensure_dir, iter_source_files, latest_file, mark_generated_dir, utc_now_iso, write_json


MESSAGE_HINTS = {
    "request": [r"request", r"req", r"read", r"write", r"invoke"],
    "response": [r"response", r"resp", r"ack", r"reply"],
    "header": [r"header", r"hdr", r"magic", r"opcode", r"function_code", r"func"],
    "length": [r"length", r"len", r"size"],
    "checksum": [r"crc", r"checksum", r"sum"],
    "address": [r"addr", r"address", r"offset"],
    "payload": [r"payload", r"data", r"body", r"pdu", r"adu"],
}


class ProtocolSpecService:
    def __init__(self, config_store: ConfigStore) -> None:
        self.config_store = config_store

    def _default_output_path(self, protocol_name: str | None = None) -> Path:
        cfg = self.config_store.get()
        base = ensure_dir(Path(cfg.legacy_paths.protocol_output_dir))
        filename = protocol_name or cfg.offline.default_protocol_filename
        if not filename.endswith('.json'):
            filename += '.json'
        return base / filename

    def analyze_source(
        self,
        source_path: str,
        output_path: str | None = None,
        protocol_name: str | None = None,
        copy_to_scan_dir: bool = False,
        **options: Any,
    ) -> dict:
        source_root = Path(source_path).expanduser().resolve()
        if not source_root.exists():
            raise FileNotFoundError(f"source path not found: {source_root}")

        structs: set[str] = set()
        functions: set[str] = set()
        keywords: set[str] = set()
        fields: dict[str, set[str]] = {key: set() for key in MESSAGE_HINTS}
        files_scanned = 0

        struct_re = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)")
        func_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        word_re = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

        for path in iter_source_files(source_root):
            files_scanned += 1
            text = path.read_text(encoding='utf-8', errors='replace')
            structs.update(struct_re.findall(text))
            for fn in func_re.findall(text):
                if fn not in {"if", "for", "while", "switch", "return", "sizeof"}:
                    functions.add(fn)
            for word in word_re.findall(text):
                lw = word.lower()
                if any(token in lw for token in ("modbus", "bacnet", "iec", "mms", "goose", "sv", "pdu", "adu", "packet", "frame", "apdu", "tpkt", "ether")):
                    keywords.add(word)
                for field_name, patterns in MESSAGE_HINTS.items():
                    if any(re.search(pattern, lw) for pattern in patterns):
                        fields[field_name].add(word)

        protocol = {
            "schema_version": "backend-rewrite.v1",
            "generated_at": utc_now_iso(),
            "source_path": str(source_root),
            "protocol_name": protocol_name or source_root.name,
            "files_scanned": files_scanned,
            "extract_options": options,
            "candidate_structs": sorted(structs)[:120],
            "candidate_functions": sorted(functions)[:240],
            "keywords": sorted(keywords)[:240],
            "field_catalog": {k: sorted(v)[:120] for k, v in fields.items()},
            "messages": self._build_messages(fields, keywords),
            "seed_templates": self._build_templates(fields, keywords),
        }

        out = Path(output_path).expanduser().resolve() if output_path else self._default_output_path(protocol_name)
        write_json(out, protocol)

        copied_to = None
        if copy_to_scan_dir:
            cfg = self.config_store.get()
            scan_dir = mark_generated_dir(ensure_dir(Path(cfg.paths.protocol_scan_dir)), 'protocol-scan')
            copied = scan_dir / out.name
            if copied.resolve() != out.resolve():
                copy_file(out, copied)
                copied_to = str(copied)

        return {"output_path": str(out), "copied_to": copied_to, "protocol": protocol}

    def latest_spec(self, directory: str | None = None) -> Path | None:
        cfg = self.config_store.get()
        scan_dir = Path(directory or cfg.paths.protocol_scan_dir)
        return latest_file(scan_dir, '*.json')

    @staticmethod
    def _build_messages(fields: dict[str, set[str]], keywords: set[str]) -> list[dict]:
        msgs = []
        header = next(iter(sorted(fields.get('header') or [])), 'HEADER')
        length = next(iter(sorted(fields.get('length') or [])), 'LEN')
        checksum = next(iter(sorted(fields.get('checksum') or [])), 'CRC')
        payload = next(iter(sorted(fields.get('payload') or [])), 'DATA')
        for name in ('request', 'response'):
            msgs.append(
                {
                    'name': name,
                    'fields': [
                        {'name': header, 'role': 'header'},
                        {'name': length, 'role': 'length'},
                        {'name': payload, 'role': 'payload'},
                        {'name': checksum, 'role': 'checksum'},
                    ],
                }
            )
        if keywords:
            msgs.append({'name': 'keyword_driven', 'fields': [{'name': item, 'role': 'hint'} for item in list(sorted(keywords))[:12]]})
        return msgs

    @staticmethod
    def _build_templates(fields: dict[str, set[str]], keywords: set[str]) -> list[dict]:
        def pick(group: str, fallback: str) -> str:
            vals = sorted(fields.get(group) or [])
            return vals[0] if vals else fallback

        header = pick('header', 'HDR')
        length = pick('length', 'LEN')
        checksum = pick('checksum', 'CRC')
        payload = pick('payload', 'PAYLOAD')
        address = pick('address', 'ADDR')
        templates = [
            {'name': 'minimal', 'format': [header, length, payload, checksum]},
            {'name': 'read_request', 'format': [header, 'READ', address, 'COUNT', checksum]},
            {'name': 'write_request', 'format': [header, 'WRITE', address, 'VALUE', checksum]},
            {'name': 'raw_payload', 'format': [header, payload, checksum]},
        ]
        if keywords:
            templates.append({'name': 'keyword_driven', 'format': list(sorted(keywords))[:12]})
        return templates
