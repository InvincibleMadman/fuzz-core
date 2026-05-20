# GDB 智能体独立调试流程

## 目标

本版本将 GDB 调试从 fuzz job artifact analyze 中解耦出来。`/api/v1/jobs/{job_id}/artifacts/{artifact_id}/analyze` 仍然保留，但它不再启动 GDB，只返回前端选择崩溃种子所需的 job、artifact、seed_path、target 和 `debug_session_request`。

真正启动 GDB 的接口是：

- `GET /api/v1/debug/candidates?job_id=...`
- `POST /api/v1/debug/sessions`
- `POST /api/v1/debug/sessions/batch`
- `GET /api/v1/debug/sessions/{session_id}`
- `GET /api/v1/protocols/{protocol}/debug/sessions`

## 业务逻辑

1. Fuzz job 或人工目录提供 crash seed。
2. 前端调用 `GET /api/v1/jobs/{job_id}/artifacts` 或 `GET /api/v1/debug/candidates?job_id=...`，得到每个 seed 的稳定 artifact_id、seed_path 和 target 模板。
3. 用户在 Web UI 中选择一个 seed 和对应测试程序。
4. 前端把 `debug_session_request` 提交到 `POST /api/v1/debug/sessions`。
5. 后端创建 `DebugSession`，进入状态机：
   `created -> launching_target -> replaying_input -> waiting_signal -> collecting_context -> llm_reasoning -> classified -> archived`。
6. `GDBDriver` 启动 gdb，采集 backtrace、threads、registers、frame locals、source location、disassembly、stdout/stderr tail。
7. `VulnerabilityClassifier` 归类错误类型、漏洞粗类型、CWE、函数名、文件和行号范围。
8. `DebugPersistence` 写入两个 JSON 文件：
   - `workspace/protocols/{protocol}/debug/sessions/{session_id}.json`
   - `workspace/protocols/{protocol}/debug/reports/{session_id}.report.json`
9. `HistoryService` 将漏洞归档到：
   - `workspace/protocols/{protocol}/history/vulns/`
   - SQLite `vuln_history` 表。

## 关键代码调用顺序

```text
api/routers/debug.py:create_debug_session
  -> DebugRequest / TargetConfig model_validate
  -> DebugSessionManager.run
      -> Replayer.replay
      -> GDBDriver.collect
          -> gdb --batch --args <binary> <args>
          -> stdin: seed bytes enter process stdin
          -> file: @@ is replaced by seed_path, or seed_path is appended
      -> VulnerabilityClassifier.classify
      -> HistoryService.archive
      -> DebugPersistence.save_report
      -> DebugPersistence.save
```

## 输出 JSON 约束

每次调试都会生成 `debug_report`，同时写入 `.report.json` 文件。前端优先渲染这些字段：

```json
{
  "schema_version": "debug-report.v1",
  "session_id": "dbg-...",
  "history_record_id": "vuln-...",
  "protocol": "modbus",
  "job_id": "job-... or null",
  "artifact": {
    "artifact_id": "artifact-...",
    "seed_path": "/path/to/crash_seed",
    "seed_name": "id:000000,sig:11"
  },
  "target": {
    "binary_path": "/path/to/target",
    "cwd": "/path/to/build",
    "args": [],
    "transport_type": "stdin"
  },
  "vulnerability_location": {
    "function_name": "parse_packet",
    "file_path": "src/parser.c",
    "line": 123,
    "line_start": 118,
    "line_end": 128
  },
  "error_type": "segmentation-fault / out-of-bounds access",
  "vuln_type": "out-of-bounds-access",
  "coarse_type": "bounds-check",
  "cwe": "CWE-125",
  "signal": "SIGSEGV",
  "exit_code": 0,
  "crash_signature": "...",
  "possible_exploitation_description": "May allow denial of service or out-of-bounds read/write...",
  "poc_concept": "The proof-of-concept input is the archived crash seed...",
  "repro_steps": [],
  "fix_suggestion": "...",
  "confidence": 0.68,
  "stack_summary": "..."
}
```

## 请求示例

从 fuzz job 中选择可调试 seed：

```bash
curl http://127.0.0.1:8000/api/v1/debug/candidates?job_id=job-xxxx
```

启动单个 seed 调试：

```bash
curl -X POST http://127.0.0.1:8000/api/v1/debug/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "modbus",
    "artifact_path": "/tmp/out/default/crashes/id:000000,sig:11",
    "artifact_id": "artifact-xxxx",
    "job_id": "job-xxxx",
    "target": {
      "binary_path": "/home/user/build/parser",
      "cwd": "/home/user/build",
      "args": [],
      "transport_type": "stdin"
    }
  }'
```

批量 seed 目录调试：

```bash
curl -X POST http://127.0.0.1:8000/api/v1/debug/sessions/batch \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "modbus",
    "seed_dir": "/tmp/crashes",
    "glob": "*",
    "max_cases": 20,
    "target": {
      "binary_path": "/home/user/build/parser",
      "cwd": "/home/user/build",
      "args": [],
      "transport_type": "stdin"
    }
  }'
```
