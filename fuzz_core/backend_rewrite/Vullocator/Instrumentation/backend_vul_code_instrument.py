from __future__ import annotations

from ...offline.instrument import InstrumentationService


def instrument_code(service: InstrumentationService, vuln_file: str, source_path: str | None = None, output_path: str | None = None):
    return service.instrument(source_path=source_path, analysis_path=vuln_file, output_path=output_path, in_place=output_path is None)
