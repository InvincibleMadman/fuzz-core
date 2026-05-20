# Data model

SQLite database: `workspace/fuzz_core.sqlite3`.

Tables:

- `vuldocs`: raw upload metadata and source path
- `kb_entries`: distilled structured vulnerability facts
- `seed_generations`: seed generation metadata including `generation_mode`
- `debug_sessions`: full debugger session lifecycle and collected context
- `vuln_history`: frontend-facing vulnerability archive

Core JSON schemas are represented by Pydantic models in `fuzz_core/models.py` and `fuzz_core/debugger/models.py`.
