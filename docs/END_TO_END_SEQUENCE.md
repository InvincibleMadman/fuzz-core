# End-to-end sequence

1. Frontend uploads vulnerability documents:
   - `POST /api/v1/protocols/opener/vuldocs/upload`
   - raw files land in `workspace/protocols/opener/vuldocs/raw/`.

2. Backend distills documents:
   - `POST /api/v1/protocols/opener/vuldocs/distill`
   - records are inserted into SQLite `kb_entries` and mirrored as JSON in `vuldocs/distilled`.

3. Frontend visualizes KB:
   - `GET /api/v1/protocols/opener/kb/summary`
   - `GET /api/v1/protocols/opener/kb/graph`
   - `GET /api/v1/protocols/opener/kb/timeline`.

4. Seed generation:
   - `POST /api/v1/offline/seeds/generate`
   - returns `generation_mode`: `spec_plus_kb`, `spec_only`, `kb_only_fallback`, `raw_doc_fallback`, or `degraded_no_spec`.

5. Fuzz job:
   - `POST /api/v1/jobs`
   - artifacts are discovered under job output crash/hang folders.

6. Crash artifact analysis:
   - `POST /api/v1/jobs/{job_id}/artifacts/{artifact_id}/analyze`
   - runner calls the debugger service.

7. Debug session:
   - replay adapter runs according to target transport settings
   - GDB collects backtrace, registers, frame locals, signal, source location and disassembly
   - local classifier assigns `coarse_type`, `vuln_type`, CWE, PoC concept and repro steps.

8. Archive:
   - debug session saved under `debug/sessions`
   - vulnerability record inserted into `vuln_history`.

9. Frontend history:
   - `GET /api/v1/protocols/opener/vulns/history?coarse_type=bounds-check`.
