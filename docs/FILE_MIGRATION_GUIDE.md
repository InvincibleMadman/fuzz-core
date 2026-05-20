# File-level migration guide

## Add directly

- `fuzz_core/storage/path_resolver.py`
- `fuzz_core/storage/repository.py`
- `fuzz_core/services/vuldoc_service.py`
- `fuzz_core/services/distill_service.py`
- `fuzz_core/services/kb_service.py`
- `fuzz_core/services/seed_service.py`
- `fuzz_core/services/risk_service.py`
- `fuzz_core/services/history_service.py`
- `fuzz_core/services/protocol_service.py`
- `fuzz_core/debugger/*`
- `fuzz_core/api/routers/protocols.py`
- `scripts/migrate_workspace.py`
- `docs/*`
- `tests/test_protocol_scope.py`

## Replace or patch carefully

- `fuzz_core/config.py`
  - keep original options but add `workspace.default_protocol`, `llm.api_key_env`, and debugger settings.
  - remove hardcoded local paths or make them config/env-controlled.

- `fuzz_core/api/app.py`
  - preserve all existing routers.
  - add service construction and include new protocol router.

- `fuzz_core/api/routers/offline.py`
  - preserve paths and response style.
  - route seed/risk/protocol logic through protocol-aware services.

- `fuzz_core/api/routers/compat.py`
  - preserve old paths and `is_success/msg/data`.
  - route upload/seed/risk/fuzz calls through services.

- `fuzz_core/runner/manager.py`
  - replace artifact `replay_artifact` and `analyze_artifact` placeholders with debugger calls.

## Migration order

1. Add storage and repository layer.
2. Add services.
3. Add debugger module.
4. Patch config and app construction.
5. Add routers.
6. Patch runner artifact methods.
7. Patch compat routes.
8. Add docs, migration script and tests.
9. Run `pytest -q`.
10. Start FastAPI and verify both `/api/v1/system/capabilities` and a legacy route.

## Compatibility notes

Do not rename existing route paths, HTTP methods or top-level wrappers. New fields are additive only.
