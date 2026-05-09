# Fuzz Core

这是一个将原 `backend` 的离线分析能力与 `Fuzz-runner` 的任务编排能力合并后的 FastAPI 核心项目。

## 设计目标

- 将协议规范分析、初始种子生成、风险路径识别、风险插桩与 AFL++ 任务管理放入单一进程项目内。
- 对 Web UI 保留 HTTP API。
- 对 React+Ink / TypeScript TUI 提供官方 **TypeScript UDS SDK**，本地调用不经过 TCP 端口。
- 仍保留 Python `LocalCoreClient`，方便 Python 侧脚本或测试直接进程内调用。
- 所有模型名、Key、目录、AFL 路径统一放到 `config.yaml`。
- 提供配置读取与修改 API。
- 保留旧 backend / runner 兼容接口，减少上层改动成本。

## 目录

```text
fuzz_core/
  api/            FastAPI 路由与应用工厂
  ipc/            UDS JSON-Lines RPC 服务
  offline/        协议分析 / 种子生成 / 风险识别 / 插桩
  runner/         AFL++ 任务、指标、崩溃采集与回放分析
  sdk.py          Python 侧进程内调用接口
  config.py       统一配置模型与持久化
packages/
  fuzz-core-client-ts/   官方 TypeScript 本地客户端
docs/
  API.md          HTTP / 兼容接口说明
```

## 启动

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FUZZ_CORE_CONFIG=./config.yaml
python -m fuzz_core.main
```

默认 HTTP 地址：`http://127.0.0.1:18000`

默认 UDS 路径：`/tmp/fuzz-core.sock`

## 统一配置 API

- `GET /api/v1/config`
- `PATCH /api/v1/config`
- `GET /api/v1/system/info`
- `GET /api/v1/system/capabilities`

PATCH 请求示例：

```json
{
  "patch": {
    "llm": {
      "base_url": "https://example.com/v1",
      "api_key": "sk-xxx",
      "models": {
        "protocol_extract": "gpt-5.4"
      }
    },
    "paths": {
      "protocol_scan_dir": "/data/specs"
    },
    "afl": {
      "afl_binary": "/opt/aflplusplus/afl-fuzz"
    }
  }
}
```

## 现代 HTTP API

### 离线能力

- `POST /api/v1/offline/protocol/analyze`
- `POST /api/v1/offline/seeds/generate`
- `POST /api/v1/offline/risk/analyze`
- `POST /api/v1/offline/risk/preview`
- `POST /api/v1/offline/risk/upload`
- `POST /api/v1/offline/instrument`

### 任务能力

- `POST /api/v1/jobs`
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

完整参数说明见 [docs/API.md](docs/API.md)。

## 兼容旧接口

已保留：

- `/extract_protocol`
- `/upload_Vuldoc`
- `/gen_init_seed`
- `/risk_code_analysis`
- `/risk_analysis_preview`
- `/riskres_upload`
- `/risk_code_instrument`
- `/fuzztesting`
- `/stop_fuzztesting`
- `/get_fuzz_stats`
- `/get_branch_coverage_history`
- `/download_fuzz_log`

## 当前实现的关键行为

### 路径与源码树

- 非 fuzz 的中间产物默认写入 `workspace/`，不会自动污染源码目录。
- 种子输出目录会写入 `.fuzz_core_generated` 标记。递归源码扫描会跳过带该标记的目录，因此即使把 seeds 放进源码树，也不会被风险分析或协议分析当成源码输入。
- 风险分析和协议分析只扫描源码类后缀：`.c/.cc/.cpp/.cxx/.h/.hpp/.py/.js/.ts/.java/.rs`。

### 风险插桩

- `source_path` 为目录且 **未指定 `output_path`** 时：默认直接**原地覆盖**源码树中的命中文件。
- `source_path` 为目录且 **指定了 `output_path`** 时：先把整个源码目录树完整复制到 `output_path`，再在复制后的对应文件上执行插桩覆盖。
- 复制模式下，不仅命中的 `.c` 文件会被改写，其他未命中的文件也会原样复制到新目录。
- 任何情况下都**不会给插桩后的文件追加后缀**。
- 因此当前版本已经**不再使用 `instrumented_dir` 或 `default_instrumented_suffix` 配置项**。

### cwd 与 AFL 路径

- 兼容接口 `/fuzztesting` 支持：`cwd`、`runCwd`、`sourceDir`、`buildDir`、`aflBinary`。
- 新接口 `/api/v1/jobs` 支持：`afl.run_cwd`、`afl.source_dir`、`afl.build_dir`、`afl.afl_binary`。
- 运行时 cwd 回退顺序为：`run_cwd -> build_dir -> source_dir -> target binary parent -> output_dir`。
- AFL 工具解析顺序为：显式请求参数 -> `afl.afl_binary` -> `afl.binary_search_paths` -> `PATH`。
- 解析结果可通过 `GET /api/v1/config` 和 `GET /api/v1/system/info` 查看。

## 满足本轮重构要求的关键点

1. **backend 与 runner 已合并**：离线分析与 AFL 任务逻辑全部位于一个项目内。
2. **改为 FastAPI**：统一由 `fuzz_core.api.app:create_app` 提供服务。
3. **TUI 可无网络调用**：优先使用 `packages/fuzz-core-client-ts`；Python 侧可使用 `fuzz_core.sdk.LocalCoreClient`。
4. **统一配置**：模型名、Base URL、Key、目录、AFL 路径都在 `config.yaml`。
5. **可修改配置**：`PATCH /api/v1/config`。
6. **种子生成输出路径可指定**：`output_dir`。
7. **协议规范输出与扫描路径解耦**：分析时可指定 `output_path`，种子生成可指定 `spec_path` 或 `spec_dir`。
8. **风险结果输出与插桩查找解耦**：风险分析可指定 `output_path`，插桩可指定 `analysis_path`。
9. **Web UI / TUI 调用链路完整**：HTTP、UDS、本地 SDK 三条路径都具备。

## TypeScript TUI 本地调用示例

```ts
import { FuzzCoreClient } from "fuzz-core-client-ts";

const client = new FuzzCoreClient({ socketPath: "/tmp/fuzz-core.sock" });

await client.config.patch({
  llm: { api_key: "sk-xxx" }
});

const protocol = await client.protocol.analyze({
  source_path: "/path/to/src",
  output_path: "/tmp/protocol.json",
  copy_to_scan_dir: true
});

const seeds = await client.seeds.generate({
  spec_path: "/tmp/protocol.json",
  output_dir: "/tmp/seeds",
  count: 16
});
```

## Python 侧进程内调用示例

```python
from fuzz_core.api.app import create_state

state = create_state("./config.yaml")
client = state.local_client

client.patch_config({"llm": {"api_key": "sk-xxx"}})

protocol = client.analyze_protocol({
    "source_path": "/path/to/target-src",
    "output_path": "/tmp/modbus_spec.json",
    "copy_to_scan_dir": True,
})
```

## 说明

当前离线分析模块实现为可运行的本地基线版本：

- 协议规范分析：基于源码结构/关键字/函数名启发式抽取
- 种子生成：基于协议规范模板输出文本/二进制种子
- 风险识别：基于风险函数与代码模式的启发式扫描
- 风险插桩：根据分析 JSON 在指定源码行前插入 `__POLAR_INS(...)`

这样做的目的是先把 **工程结构、调用链路、路径配置、接口兼容层** 一次理顺。后续你再把现有 backend 里的 LLM 调用、Vullocator、真实协议提取与插桩实现替换进 `offline/` 模块即可，不需要再次大改整体架构。
