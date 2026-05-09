# API 文档

本文档描述当前核心项目的 HTTP 接口、兼容接口和与路径 / cwd / 插桩相关的默认行为。

## 响应封装

现代接口大多返回：

```json
{
  "is_success": true,
  "success": true,
  "code": 200,
  "msg": "ok",
  "data": {}
}
```

旧 backend 兼容接口继续返回原风格 `is_success/msg/data` 包装。

## 配置与系统信息

### GET `/api/v1/config`
返回当前配置，并附带 `runtime_info.resolved_afl_tools`。

### PATCH `/api/v1/config`
按补丁方式更新配置。

请求体：

```json
{
  "patch": {
    "llm": {
      "api_key": "sk-xxx"
    },
    "afl": {
      "afl_binary": "/opt/aflplusplus/afl-fuzz"
    }
  }
}
```

### GET `/api/v1/system/info`
返回运行环境、已解析的 AFL 工具路径、任务系统状态等。

### GET `/api/v1/system/capabilities`
返回当前支持的能力列表。

## 离线能力接口

### POST `/api/v1/offline/protocol/analyze`

请求体：

```json
{
  "source_path": "/path/to/src",
  "output_path": "/tmp/protocol.json",
  "protocol_name": "modbus",
  "copy_to_scan_dir": true,
  "lang": "c",
  "implementation": "",
  "protocol_style": "auto",
  "profile": "auto",
  "protocol_variant": "",
  "iterations": 1,
  "temperature": 0.2,
  "max_tokens": 4000,
  "base_url": null,
  "api_key": null,
  "model": null
}
```

说明：
- `source_path` 必填。
- `output_path` 省略时会写入默认协议目录。
- `copy_to_scan_dir=true` 时，会额外镜像到 `paths.protocol_scan_dir`。

### POST `/api/v1/offline/seeds/generate`

请求体：

```json
{
  "spec_path": "/tmp/protocol.json",
  "spec_dir": null,
  "output_dir": "/tmp/seeds",
  "count": 8,
  "binary": false,
  "issue_doc_dir": null,
  "use_uploaded_vuldocs": false
}
```

说明：
- `spec_path` 与 `spec_dir` 二选一。
- `output_dir` 省略时使用默认种子目录。
- 输出目录会被写入 `.fuzz_core_generated` 标记。后续源码扫描会跳过该目录。

### POST `/api/v1/offline/risk/analyze`

请求体：

```json
{
  "source_path": "/path/to/src",
  "output_path": "/tmp/final_analysis.json",
  "copy_to_scan_dir": true,
  "iterations": 1,
  "temperature_coefficient": 0.2,
  "max_tokens": 4000
}
```

说明：
- `source_path` 必填。
- 只会递归扫描源码类后缀。
- 带 `.fuzz_core_generated` 标记的目录会被跳过。

### POST `/api/v1/offline/risk/preview`

请求体：

```json
{
  "analysis_path": "/tmp/final_analysis.json"
}
```

说明：
- 省略 `analysis_path` 时，读取最近一次风险分析输出。

### POST `/api/v1/offline/risk/upload`
`multipart/form-data`，字段：`file`。

说明：
- 上传后的风险分析文件会保存到兼容目录，并同步为默认风险结果文件名。

### POST `/api/v1/offline/instrument`

请求体：

```json
{
  "source_path": "/path/to/src",
  "analysis_path": "/tmp/final_analysis.json",
  "output_path": "/tmp/instrumented-src",
  "in_place": false
}
```

当前实际行为：
- `source_path` 为目录且 **未指定 `output_path`** 时，默认直接原地覆盖命中的源文件。
- `source_path` 为目录且 **指定了 `output_path`** 时，先完整复制整个源码树到 `output_path`，再在复制后的对应文件上执行插桩覆盖。
- 复制模式下会保留非 `.c` 文件等其他文件。
- 任何情况下都不会追加 `.instrumented` 等后缀。
- `in_place` 仍被兼容接受，但当前默认规则已经足以覆盖绝大多数场景。

## 任务接口

### POST `/api/v1/jobs`

请求体核心结构：

```json
{
  "name": "demo",
  "afl": {
    "afl_binary": "afl-fuzz",
    "target_binary": "/path/to/target",
    "input_dir": "/path/to/seeds",
    "output_dir": "/path/to/out",
    "run_cwd": "/path/to/run-cwd",
    "source_dir": "/path/to/source",
    "build_dir": "/path/to/build",
    "target_args": [],
    "fuzzer_args": [],
    "env": {},
    "workers": 1
  },
  "replay": {
    "enabled": true,
    "timeout_sec": 30,
    "env": {}
  },
  "debug": {
    "enabled": false,
    "command": ["gdb", "--batch"]
  },
  "analysis_policy": {
    "enabled": true,
    "modes": ["stdout", "basic"]
  },
  "metadata": {}
}
```

cwd 解析顺序：
- `afl.run_cwd`
- `afl.build_dir`
- `afl.source_dir`
- `target_binary` 所在目录
- `output_dir`

AFL 工具解析顺序：
- 请求中的 `afl.afl_binary`
- 配置中的 `afl.afl_binary`
- `afl.binary_search_paths`
- `PATH`

### 其他任务接口

- `GET /api/v1/jobs`
- `GET /api/v1/jobs/{job_id}`
- `POST /api/v1/jobs/{job_id}/stop`
- `GET /api/v1/jobs/{job_id}/metrics`
- `GET /api/v1/jobs/{job_id}/metrics/history`
- `GET /api/v1/jobs/{job_id}/artifacts`
- `GET /api/v1/jobs/{job_id}/artifacts/{artifact_id}`
- `POST /api/v1/jobs/{job_id}/artifacts/{artifact_id}/replay`
- `POST /api/v1/jobs/{job_id}/artifacts/{artifact_id}/analyze`
- `GET /api/v1/jobs/{job_id}/logs/tail`
- `GET /api/v1/jobs/{job_id}/logs/download`
- WebSocket: `/api/v1/jobs/{job_id}/events/ws`
- WebSocket: `/api/v1/jobs/{job_id}/metrics/ws`
- WebSocket: `/api/v1/jobs/{job_id}/artifacts/ws`

## 旧 backend 兼容接口

### POST `/extract_protocol`
兼容字段：`src` / `sourcePath` / `source_path`，以及 `out` / `outputPath` / `output_path`。

### POST `/upload_Vuldoc`
`multipart/form-data`，字段：`file`。上传文件会进入旧 backend 兼容目录。

### POST `/gen_init_seed`
兼容字段：
- `specPath` / `spec_path`
- `specDir` / `spec_dir`
- `outputPath` / `output_dir`
- `count`
- `binary`

### POST `/risk_code_analysis`
兼容字段：`sourcePath` / `source_path`、`outputPath` / `output_path`。

### GET `/risk_analysis_preview`
兼容查询参数：`analysisPath` / `analysis_path`。

### POST `/riskres_upload`
`multipart/form-data`，字段：`file`。

### POST `/risk_code_instrument`
兼容字段：
- `targetPath` / `sourcePath` / `source_path`
- `analysisPath` / `analysis_path`
- `outputPath` / `output_path`
- `inPlace`

默认插桩行为与现代接口相同：目录输入无输出目录时原地覆盖；有输出目录时完整复制源码树后在副本上覆盖。

### POST `/fuzztesting`
兼容字段：
- `seedPath`
- `outputPath`
- `targetPath`
- `cwd` / `runCwd`
- `sourceDir`
- `buildDir`
- `aflBinary`
- `aflArgs`
- `targetArgs`
- `workers`
- `riskAware`

说明：
- `seedPath`、`outputPath`、`targetPath` 为必填。
- `riskAware=true` 时会自动附加 `-P`。
- 当配置中启用 `use_preeny_desock` 且 `preeny_desock_path` 存在时，会自动注入 `LD_PRELOAD`。

### POST `/stop_fuzztesting`
支持按以下任一字段停止任务：
- `jobId`
- `pid`
- `outputPath` / `outputpath`

### GET `/get_fuzz_stats`
查询参数：`outputpath` / `outputPath`。

### GET `/get_branch_coverage_history`
查询参数：`outputpath` / `outputPath`。

### GET `/download_fuzz_log`
查询参数：`dbPath` / `db_path`。
