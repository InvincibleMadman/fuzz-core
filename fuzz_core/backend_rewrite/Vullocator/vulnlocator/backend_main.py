from __future__ import annotations

from ...offline.risk import RiskAnalysisService


def static_analysis(service: RiskAnalysisService, root: str, output: str, base_dir=None):
    return service.analyze(root, output_path=output, copy_to_scan_dir=False, base_dir=base_dir)
