from __future__ import annotations

from pathlib import Path

from ...offline.protocol import ProtocolSpecService


def extract_protocol(
    service: ProtocolSpecService,
    src,
    out,
    protocol,
    lang='c',
    implementation='',
    protocol_style='auto',
    profile='auto',
    protocol_variant='',
    config_file=None,
    config_text=None,
    iterations=None,
    temperature=None,
    max_tokens=None,
    base_url=None,
    api_key=None,
    model=None,
):
    result = service.analyze_source(
        source_path=src,
        output_path=str(Path(out).expanduser().resolve()),
        protocol_name=protocol,
        copy_to_scan_dir=False,
        lang=lang,
        implementation=implementation,
        protocol_style=protocol_style,
        profile=profile,
        protocol_variant=protocol_variant,
        config_file=config_file,
        config_text=config_text,
        iterations=iterations,
        temperature=temperature,
        max_tokens=max_tokens,
        base_url=base_url,
        api_key=api_key,
        model=model,
    )
    return result['output_path']
