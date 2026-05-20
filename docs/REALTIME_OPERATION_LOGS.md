# 后端中间过程日志 API

## 设计目标

协议规范提取、种子生成、风险路径识别、风险插桩、VulDoc 上传和蒸馏等同步接口，现在都会写入 `workspace/operations/*.jsonl`。前端可以在请求前生成一个 `operation_id`，放入请求体或 `X-Operation-Id` 请求头，然后在请求未结束时轮询或 WebSocket 订阅日志。

## 可调用 API

- `GET /api/v1/operations`
- `GET /api/v1/operations/{operation_id}`
- `GET /api/v1/operations/{operation_id}/logs/tail?since=0&limit=200`
- `WebSocket /api/v1/operations/{operation_id}/logs/ws`

## 前端推荐调用方式

1. 前端生成 `operation_id`，例如 `op-risk-20260520-001`。
2. 发起风险分析：

```bash
curl -X POST http://127.0.0.1:8000/api/v1/offline/risk/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "bacnet",
    "source_path": "/home/user/project",
    "operation_id": "op-risk-20260520-001"
  }'
```

3. 同时轮询日志：

```bash
curl "http://127.0.0.1:8000/api/v1/operations/op-risk-20260520-001/logs/tail?since=0&limit=100"
```

4. 或使用 WebSocket：

```text
ws://127.0.0.1:8000/api/v1/operations/op-risk-20260520-001/logs/ws
```

## 日志事件格式

```json
{
  "operation_id": "op-risk-20260520-001",
  "at": "2026-05-20T...Z",
  "level": "info",
  "stage": "scan_start",
  "message": "Scanning source tree for risk-sensitive files",
  "data": {
    "source_path": "/home/user/project"
  },
  "seq": 1
}
```

## 已接入日志的接口

现代接口：

- `POST /api/v1/offline/protocol/analyze`
- `POST /api/v1/offline/seeds/generate`
- `POST /api/v1/offline/risk/analyze`
- `POST /api/v1/offline/risk/preview`
- `POST /api/v1/offline/risk/upload`
- `POST /api/v1/offline/instrument`
- `POST /api/v1/protocols/{protocol}/vuldocs/upload`
- `POST /api/v1/protocols/{protocol}/vuldocs/distill`

兼容接口：

- `/extract_protocol`
- `/upload_Vuldoc`
- `/gen_init_seed`
- `/risk_code_analysis`
- `/risk_analysis_preview`
- `/riskres_upload`
- `/risk_code_instrument`

旧前端不传 `operation_id` 也能继续使用；新前端传入后即可实时展示中间过程。
