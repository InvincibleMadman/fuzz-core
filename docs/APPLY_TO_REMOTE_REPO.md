# 将本源码包应用到 fuzz-core 远程仓库的逐文件指导

> 本指导按当前压缩包中的项目结构编写。迁移前建议在原仓库新建分支，例如 `feature/standalone-gdb-debug-and-operation-logs`。

## 迁移顺序建议

1. 先同步模型与状态容器。
2. 再同步 debugger、runner、service。
3. 再同步 API router 与 app 注册。
4. 最后同步测试与文档。
5. 运行 `pytest -q`，再手工验证 `uvicorn fuzz_core.main:app --reload`。

## 新增文件

| 路径 | 动作 | 说明 | 前置依赖 |
|---|---|---|---|
| `fuzz_core/api/routers/debug.py` | 新增 | 独立 GDB 调试 API，不依赖 fuzz job analyze 启动 | `debugger/*`, `runner.manager` |
| `fuzz_core/api/routers/operations.py` | 新增 | 中间过程日志查询与 WebSocket 输出 | `services/operation_log_service.py` |
| `fuzz_core/services/operation_log_service.py` | 新增 | 文件型 JSONL 操作日志服务 | `models.now_iso` |
| `docs/GDB_DEBUG_WORKFLOW.md` | 新增 | GDB 业务流程、调用顺序、JSON 输出约束 | 无 |
| `docs/REALTIME_OPERATION_LOGS.md` | 新增 | 前端实时日志区域对接说明 | 无 |
| `docs/APPLY_TO_REMOTE_REPO.md` | 新增 | 本文件，迁移说明 | 无 |

## 修改文件

| 路径 | 动作 | 说明 | 兼容性注意 |
|---|---|---|---|
| `fuzz_core/api/app.py` | 修改 | 注册 `debug` 和 `operations` router，初始化 `OperationLogService` | 不删除现有 router |
| `fuzz_core/state.py` | 修改 | `CoreState` 增加 `operations` 字段 | 仅内部状态扩展 |
| `fuzz_core/runner/manager.py` | 替换/修改 | `artifact_id` 改为 SHA-256 稳定 hash；artifact 列表暴露 `seed_path`、`target`、`debug_session_request`；`analyze_artifact` 不再启动 GDB | 保留原 API 路径，但语义变为返回调试启动模板 |
| `fuzz_core/api/routers/jobs.py` | 修改 | 增加 `/api/v1/jobs/{job_id}/debug/candidates`；原 artifacts/analyze 路由保留 | 现有路径不删不改 |
| `fuzz_core/debugger/gdb_driver.py` | 替换/修改 | 支持 stdin 和 file/`@@` seed 注入；合并系统 env；增强输出解析 | 无外部在线依赖 |
| `fuzz_core/debugger/classifier.py` | 替换/修改 | 增加 `error_type`、`line_range`、`possible_exploitation_description` | 输出字段只增不删 |
| `fuzz_core/debugger/persistence.py` | 修改 | 新增 `save_report()`，写入 `.report.json` | 保留原 session JSON |
| `fuzz_core/debugger/session_manager.py` | 替换/修改 | 生成受约束 `debug_report` JSON，并写入 `debug/reports` | `DebugSessionManager.run()` 仍兼容 dict 和 DebugRequest |
| `fuzz_core/api/routers/offline.py` | 替换/修改 | 现代离线接口接入 operation log | 旧请求体不提供 `operation_id` 仍可用 |
| `fuzz_core/api/routers/protocols.py` | 替换/修改 | VulDoc 上传、蒸馏接入 operation log | 旧响应字段保留，新增 `operation_id` |
| `fuzz_core/api/routers/compat.py` | 替换/修改 | 兼容接口接入 operation log，响应保持 `is_success/msg/data` | 外层包装不变 |
| `tests/test_protocol_scope.py` | 修改 | 增加稳定 artifact、独立 debug、operation log 测试 | 测试依赖 httpx/TestClient |
| `pyproject.toml` | 修改 | 可将版本号改为 `0.2.1` | 可选 |
| `README.md` | 修改 | 建议同步新增 API 简介 | 可选但推荐 |

## 删除动作

没有必须删除的源码文件。建议删除提交中的 `__pycache__`、`.pytest_cache`、本地 `workspace/`。

## 导入调整

`fuzz_core/api/app.py` 需要新增：

```python
from ..services.operation_log_service import OperationLogService
```

并将：

```python
from .routers import config_router, system, offline, protocols, jobs, debug, operations as operations_router, compat
```

注册顺序建议：

```python
app.include_router(config_router.router)
app.include_router(system.router)
app.include_router(offline.router)
app.include_router(protocols.router)
app.include_router(jobs.router)
app.include_router(debug.router)
app.include_router(operations_router.router)
app.include_router(compat.router)
```

## API 兼容性说明

- 没有删除现有 `/api/v1/jobs/{job_id}/artifacts/{artifact_id}/analyze`。
- 但该接口不再启动 GDB，而是返回 `debug_session_request` 给前端。
- 前端启动 GDB 应改用 `POST /api/v1/debug/sessions`。
- 旧兼容接口仍返回 `is_success/msg/data`。
- 现代接口仍返回 `ok/message/data`。
- 新增字段包括 `operation_id`、`seed_path`、`debug_session_request`、`debug_report`，旧前端忽略即可。

## 验证命令

```bash
pip install -r requirements.txt
pytest -q
uvicorn fuzz_core.main:app --reload
```

## 手工验证 GDB 独立调试

```bash
curl -X POST http://127.0.0.1:8000/api/v1/debug/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "modbus",
    "artifact_path": "/tmp/crashes/id_000001",
    "target": {
      "binary_path": "/path/to/parser",
      "cwd": "/path/to/build",
      "args": [],
      "transport_type": "stdin"
    }
  }'
```
