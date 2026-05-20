# Audit summary

## New backend observations

The public `fuzz-core` README exposes a FastAPI backend with modern `/api/v1/...` routes, legacy-compatible routes, offline services, runner, IPC and workspace-oriented storage. The existing documented behavior also states that generated artifacts should go to workspace and that `.fuzz_core_generated` must be skipped during source scans.

Observed design gaps that this package fixes:

- protocol-independent shared path use in configuration and offline flows
- placeholder runner artifact replay/analyze behavior
- missing formal VulDoc upload → distill → KB → seed generation loop
- missing front-end friendly KB graph/timeline/summary interfaces
- missing generalized, persistent GDB debug sessions and vulnerability history records

## Old backend extraction

The old Flask backend contains valuable route-level flow for:

- `/upload_Vuldoc`
- `/gen_init_seed`
- `/risk_code_analysis`
- `/riskres_upload`
- `/risk_code_instrument`
- `/fuzztesting`

But it also mixes data through shared directories such as VulDoc/risk upload folders, uses `final_analysis.json` as a shared result file, and contains local hardcoded paths. This package keeps the flow idea but reimplements it behind service/repository layers.

## GDB prototype

No concrete GDB prototype archive was available in the file library during packaging. The debugger module is therefore implemented from the requested contract rather than copied from a prototype. It uses a generic target model, replay adapters, GDB collection, classification, persistence and vulnerability history.
