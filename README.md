# ThreatHunter Agent

一个自主网络安全调查 Agent：未来根据安全告警自主制定调查计划、调用安全工具、收集证据并生成事件调查报告。

## 当前开发状态

当前完成 **T01：项目骨架与工程环境初始化**、**T02：核心领域 Schema 与数据契约**、
**T03：安全调查 Benchmark V1**、**T04：确定性调查工具层** 与
**T05：确定性调查编排运行时**。

已经具备的能力：

- 可安装的 Python 项目骨架（`pyproject.toml` + 包目录结构）
- 基于 `pydantic-settings` 的配置系统（支持 `.env`）
- 基于 FastAPI 的最小应用，只暴露 `GET /health`
- PostgreSQL 16 的 Docker Compose 编排（仅数据库容器，无业务表）
- 基于 pytest + FastAPI TestClient 的冒烟测试
- Pydantic v2 领域数据契约：告警、调查计划、工具调用、证据、结论、报告（含 ID 前缀、
  时区与各类一致性校验），供后续 Dataset / Tools / Evidence Store / RAG / MCP /
  LangGraph / Agent / Evaluation 共同复用
- 8 个 Case 的调查 Benchmark：合成但真实的 telemetry、共享知识库、Evaluation-only
  Ground Truth、数据集 Loader 与跨文件 Dataset Validation
- 5 个确定性的只读调查工具（endpoint / network+DNS / file reputation / IOC
  reputation / CTI+ATT&CK），通过 `ToolExecutor` 产出 T02 `ToolResult`
- 确定性调查编排运行时：Alert → Plan → Step → PlannerDecision → ToolCall →
  ToolResult → Step 完成 → `InvestigationRun`，含运行时状态、ID 生命周期、
  ToolCall/Step 状态机、retry、budget、trajectory 与内存持久化

尚未实现（属于后续 Task）：LLM 调用、LangGraph、Prompt、Evidence 提炼与 Evidence
Store、Finding / Verdict / 置信度计算、RAG / Embedding / Vector DB、MCP、数据库持久化、
Evaluation runner、前端界面。

本仓库当前不存在任何 AI 依赖，也不包含任何 API Key。

## Python 要求

- Python >= 3.11（开发环境使用 3.13）
- Windows / Linux 均可运行

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

复制示例配置（可选，缺省值即可让服务启动）：

```powershell
Copy-Item .env.example .env
```

## 配置项

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `APP_NAME` | `threathunter-agent` | 服务名，`/health` 的 `service` 字段来源 |
| `APP_VERSION` | `0.1.0` | 版本号，`/health` 的 `version` 字段来源 |
| `DATABASE_URL` | `postgresql+psycopg://threathunter:threathunter@localhost:5432/threathunter` | 数据库连接串 |
| `LLM_PROVIDER` | `deepseek` | 预留的模型提供方配置 |
| `LLM_MODEL` | `deepseek-chat` | 预留的模型名称配置 |
| `LLM_API_KEY` | 空 | 必须由本机环境或 `.env` 提供，仓库中不硬编码 |

## 领域 Schema

所有数据契约从 `app.schemas` 统一导入，例如 `from app.schemas import Evidence, SecurityAlert`。

| 模块 | 内容 |
| --- | --- |
| `app/schemas/common.py` | ID 前缀校验、时区规范化、0~1 分数与重用类型别名 |
| `app/schemas/alert.py` | `SecurityAlert`、`AlertSeverity` |
| `app/schemas/investigation.py` | `InvestigationPlan`、`InvestigationStep` 及其状态机校验 |
| `app/schemas/tools.py` | `ToolCall`、`ToolResult`（工具原始结构化返回） |
| `app/schemas/evidence.py` | `Evidence`、`EvidenceProvenance`（规范化证据 + 来源） |
| `app/schemas/findings.py` | `IOCFinding`、`AttackTechniqueFinding` 及其类型枚举 |
| `app/schemas/report.py` | `InvestigationReport`、`TimelineEvent`、`Recommendation` |
| `app/schemas/health.py` | `HealthResponse` |

约定：

- ID 只校验前缀（`ALT-`、`INC-`、`PLAN-`、`STEP-`、`TC-`、`TR-`、`EV-`、`IOCF-`、`RPT-`），
  因此 `ALT-001` 这类人工可读 ID 合法，不强制 UUID。
- 所有 `datetime` 必须 timezone-aware，校验时统一转换为 UTC，JSON 输出为 ISO 8601。
- `ToolResult` 是工具执行的原始结构化返回，`Evidence` 是从 `ToolResult` / Alert / Knowledge
  提炼并规范化后的证据，两者不合并；`Evidence` 必须带 provenance，
  `provenance.raw_ref` 指向原始数据位置。
- `Evidence.reliability` 表示来源/观测本身的可信程度；`Finding` / `Report` 的 `confidence`
  表示证据对结论的支持强度。本阶段只约束取值范围为 0~1，不实现置信度计算。
- `malicious` / `suspicious` 的结论必须至少有一条 Evidence 支撑；`inconclusive` 允许没有证据。

## 调查 Benchmark（T03）

Benchmark 是 **synthetic-but-realistic**（合成但贴近真实）且 **deterministic** 的：
所有 timestamp 都是固定时间的 UTC，事件 ID 与内容可复现，不存在随机生成。
恶意/可疑公网地址只使用 RFC 5737 文档网段（`192.0.2.0/24`、`198.51.100.0/24`、
`203.0.113.0/24`），域名只使用 `example.com` / `example.net` / `example.org`，
内部流量使用 RFC 1918 私网地址，所有 SHA256 均为合成值，不含真实恶意基础设施。

### 三个目录的职责

| 目录 | 职责 | 可见性 |
| --- | --- | --- |
| `datasets/cases/` | 每个 Case 的 metadata、initial alert 与 telemetry（endpoint / network / dns / files） | Agent 运行时可见 |
| `datasets/knowledge/` | 共享知识：IOC reputation、synthetic CTI 记录、本项目用到的 ATT&CK 子集 | Agent 运行时可见 |
| `datasets/ground_truth/` | 期望判定、期望 IOC/Technique、key/acceptable evidence、期望调查来源 | **仅 Evaluation** |

Ground Truth 只允许通过 `GroundTruthLoader` 读取；`BenchmarkLoader` 不提供任何
Ground Truth 接口（没有 `load_ground_truth`，也没有会一并返回答案的 `load_everything`），
这条边界由测试固定下来，而不是靠约定。

### 8 个 Case

| Case | 名称 | 难度 | Ground Truth | 说明 |
| --- | --- | --- | --- | --- |
| CASE-001 | Encoded PowerShell Download & Execute | easy | malicious | Office 文档触发 encoded PowerShell，下载脚本与二进制 |
| CASE-002 | Credential Dumping Followed by C2 | medium | malicious | LSASS 凭据转储后连接外部 C2 |
| CASE-003 | DNS Beaconing | medium | malicious | 固定 5 分钟间隔的 DNS beacon 与外联 |
| CASE-004 | LOLBin Download Chain | medium | malicious | certutil 下载归档、解压并执行 |
| CASE-005 | Admin PowerShell Maintenance | medium | benign | hard negative：与 CASE-001 表面相似，但为审批过的运维行为 |
| CASE-006 | Developer Download / Hash False Positive | easy/medium | benign | 正常软件分发下载；未知 hash 不等于恶意 |
| CASE-007 | Suspicious Authentication | medium | suspicious | 多次登录失败后成功登录，来自异常外部地址 |
| CASE-008 | Incomplete Telemetry Investigation | hard | inconclusive | 证据故意不足，无法判定 benign / malicious |

判定分布：malicious 4、benign 2、suspicious 1、inconclusive 1。
每个 Case 都同时包含相关事件与合理的噪声事件（例如 `explorer.exe`、`chrome.exe`、
`svchost.exe`、`Teams.exe` 的正常行为，正常 HTTPS 与内网流量）。

### Telemetry 记录数

| Case | Endpoint | Network | DNS | Files | 合计 |
| --- | --- | --- | --- | --- | --- |
| CASE-001 | 14 | 11 | 9 | 5 | 39 |
| CASE-002 | 16 | 10 | 7 | 4 | 37 |
| CASE-003 | 12 | 12 | 14 | 3 | 41 |
| CASE-004 | 13 | 9 | 7 | 5 | 34 |
| CASE-005 | 15 | 9 | 6 | 4 | 34 |
| CASE-006 | 12 | 9 | 6 | 5 | 32 |
| CASE-007 | 16 | 8 | 5 | 3 | 32 |
| CASE-008 | 14 | 8 | 5 | 4 | 31 |
| **合计** | **112** | **76** | **59** | **33** | **280** |

共享知识：27 条 IOC reputation、4 条 synthetic CTI 记录、6 条 ATT&CK Technique。

### 使用方式

```python
from app.benchmark import BenchmarkLoader, GroundTruthLoader, validate_dataset

loader = BenchmarkLoader()                     # Agent 侧：只读 cases / knowledge
alert = loader.load_initial_alert("CASE-001")  # 直接返回 T02 的 SecurityAlert
events = loader.load_endpoint_events("CASE-001")
iocs = loader.load_ioc_reputation_records()

truth = GroundTruthLoader().load_ground_truth("CASE-001")   # 仅 Evaluation 使用

report = validate_dataset()                    # 跨文件 Dataset Validation
assert report.ok
```

`validate_dataset()` 校验 8 个 Case 是否齐全、metadata / alert / telemetry / ground truth
是否合法、Ground Truth 引用的 `EPE-` / `NET-` / `DNS-` / `FILE-` ID 是否真实存在、
期望 IOC 与 Technique 是否有数据或知识支撑、Case 内 ID 是否唯一、时间是否为 UTC、
以及判定分布是否符合定义。

### 数据集命令

```powershell
# 完整测试（含 Dataset Validation 与 Ground Truth 隔离测试）
python -m pytest

# 只跑数据集校验
.\.venv\Scripts\python.exe -c "from app.benchmark import validate_dataset; r = validate_dataset(); print(r.ok, r.issues)"
```

## 调查工具层（T04）

工具层是**确定性只读查询层**：只回答"telemetry / knowledge 里有什么"，不做安全结论推理。
每个工具接收一个 Pydantic v2 输入 Schema，返回该工具自己的 typed payload。

| Tool | 作用 | 数据来源 |
| --- | --- | --- |
| `search_endpoint_events` | 按事件类型、主机、用户、进程、命令行、路径、hash、时间窗查询端点 telemetry | `cases/<CASE>/telemetry/endpoint_events.json` |
| `search_network_activity` | 同时查询 network 与 DNS telemetry（每源独立过滤、排序、limit、truncation） | `network_events.json` / `dns_events.json` |
| `lookup_file_reputation` | 按 hash / path / file_name（+host）查询文件 telemetry，并用 SHA256 补充 reputation | `files.json` + `knowledge/ioc_reputation.json` |
| `lookup_ioc_reputation` | 精确查询某个 indicator 的全部 reputation 记录（可限定 IOC 类型） | `knowledge/ioc_reputation.json` |
| `search_cti` | 同时搜索 CTI 记录与 ATT&CK 技术，两类结果分开返回 | `knowledge/cti_records.json` / `attack_techniques.json` |

关键语义：

- `ToolResult` 是**工具的原始结构化返回**（`payload.model_dump(mode="json")`），不是
  `Evidence`，也不是 `Finding`：工具不创建 evidence、不计算置信度、不给 verdict。
- **0 结果是成功查询**：返回空列表与 `count=0`，不是异常；只有参数非法、tool 名未知或
  数据集错误才产生 `success=False` 的 `ToolResult`。
- **IOC unknown ≠ IOC absent**：知识库中存在 `reputation=unknown` 的记录时
  `found=True` 并返回记录，只有知识库完全没有该 indicator 时才 `found=False`。
- 工具层无法访问 Ground Truth：`app/tools` 不 import `GroundTruthLoader`，只读取
  `datasets/cases` 与 `datasets/knowledge`（由测试强制）。
- 查询语义固定：ID / SHA256 精确匹配，IP 归一化精确匹配，文本字段大小写无关精确匹配，
  `command_line_contains` / `query_contains` 与 CTI 自由文本为大小写无关子串匹配，
  时间窗两端闭区间；不同 filter 之间 AND，同字段列表内 OR；telemetry 按
  `timestamp ASC, record ID ASC` 排序。

```python
from app.schemas.tools import ToolCall
from app.tools import EndpointSearchInput, ToolExecutor, search_endpoint_events

payload = search_endpoint_events(
    EndpointSearchInput(case_id="CASE-001", process_name="powershell.exe")
)  # payload.count / payload.items / payload.truncated

call = ToolCall(
    tool_call_id="TC-001", incident_id="INC-001", step_id="STEP-001",
    tool_name="search_endpoint_events",
    arguments={"case_id": "CASE-001", "event_types": ["process_creation"]},
    status="requested", requested_at="2026-03-02T09:20:00Z",
)
result = ToolExecutor().execute(call)   # T02 ToolResult，data 为 JSON dict
```

`ToolExecutor` 只负责执行与计时：它不修改传入的 `ToolCall`，也不管理
`requested -> running -> succeeded/failed` 生命周期（由未来编排层负责）。

## 调查编排运行时（T05）

`app/runtime` 是一个 **framework-agnostic 的确定性运行时**（无 LLM、无 LangGraph），
它把一次告警推进为一份可复现的调查记录：

```
SecurityAlert → InvestigationPlan → InvestigationStep → PlannerDecision
→ ToolCall → ToolExecutor → ToolResult → Step 完成 → InvestigationRun
```

已支持的能力：

- **Planner / Runtime 解耦**：`InvestigationPlanner` 协议 + `DeterministicPlanner`；
  planner 只能返回 `PlannerDecision`，不能执行工具、不能访问 loader 或 Ground Truth，
  只通过 `PlanningContext`（alert / plan / current step / 历史 tool calls 与 results /
  剩余预算）观察上下文。LangGraph 未来只能作为 adapter。
- **状态机**：Step `pending → running → completed|failed`（不允许 terminal 回退）；
  ToolCall `requested → running → succeeded|failed`，由 runtime 负责。
- **ID 归属**：`INC-*`/`TC-*` 由 runtime 生成，`PLAN-*`/`STEP-*` 由 planner 生成，
  `ALT-*` 来自数据集，`TR-*` 仍由 T04 executor 生成。
- **Retry**：失败结果按 `RetryPolicy` 判定是否重试；重试总是创建**新的** `ToolCall`，
  旧 call 保持 failed；invalid arguments / unknown tool 默认不重试。
- **Budget**：`max_steps` / `max_tool_calls` / `max_tool_calls_per_step` / `max_failures`，
  超限时 `RuntimeStatus.budget_exhausted` 且不再执行新 tool。
- **Trajectory**：append-only，`sequence` 是唯一权威顺序；details 只存标量（敏感键、
  payload 容器、traceback 一律丢弃），完整 `ToolResult` 只通过 `tool_result_id` 引用。
- **T06 handoff**：`InvestigationRun` 保留全部 `ToolCall` + `ToolResult`（含 payload）与
  trajectory，供 T06 构建 `ToolCall → ToolResult → Evidence → EvidenceProvenance`。
  T05 自身不创建 Evidence。

```python
from app.agents import DeterministicPlanner
from app.benchmark import BenchmarkLoader
from app.runtime import InvestigationRuntime
from app.tools import ToolExecutor

loader = BenchmarkLoader()
run = InvestigationRuntime(
    DeterministicPlanner(case_id="CASE-001"),
    executor=ToolExecutor(loader=loader),
).run(loader.load_initial_alert("CASE-001"))

run.status, run.stop_reason, run.tool_calls, run.trajectory
```

仍**未实现**：LLM / Prompt、LangGraph、Evidence 提炼、RAG / Embedding / Vector DB、
MCP、数据库持久化（当前只有内存 store）、Evaluation runner。

## 启动 FastAPI

```powershell
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

验证：

```powershell
curl.exe http://127.0.0.1:8000/health
```

返回：

```json
{"status": "ok", "service": "threathunter-agent", "version": "0.1.0"}
```

交互式文档：http://127.0.0.1:8000/docs

## 运行测试

```powershell
python -m pytest
```

## 启动 PostgreSQL

```powershell
docker compose up -d postgres
```

连接信息：主机 `localhost`，端口 `5432`，数据库 / 用户名 / 密码均为 `threathunter`。
数据保存在 Docker volume `threathunter_pgdata` 中。

停止容器（保留数据）：

```powershell
docker compose down
```

## 目录结构

```text
app/            应用代码（main.py 为 FastAPI 入口，core/config.py 为配置）
  benchmark/    Benchmark 数据集 Schema、Loader 与 Dataset Validation
  runtime/      确定性调查编排运行时（contracts / budget / retry / trajectory / store / runtime）
  agents/       Planner（协议 + DeterministicPlanner）
  graph/        编排图（后续 Task）
  tools/        确定性调查工具层（contracts / 5 个工具 / executor）
  rag/          检索增强（后续 Task）
  mcp/          MCP 集成（后续 Task）
  evidence/     证据模型与推理（后续 Task）
  db/           持久化层（后续 Task）
  schemas/      Pydantic v2 领域数据契约
  core/         配置与核心基础设施
datasets/       本地数据集（cases 告警样本与 telemetry、knowledge 共享知识、ground_truth 评测答案）
evaluation/     评测脚本与结果
frontend/       前端入口（后续 Task）
scripts/        运维 / 辅助脚本
tests/          pytest 测试（tests/schemas 领域契约、tests/benchmark 数据集、tests/tools 工具层、tests/runtime 运行时）
```

## Roadmap

- T01 项目骨架与工程环境初始化（已完成）
- T02 核心领域 Schema 与数据契约（已完成）
- T03 安全调查 Benchmark V1（已完成：8 Case / telemetry / 共享知识 / Ground Truth / Loader / Dataset Validation）
- T04 确定性调查工具层（已完成：5 个 Tool / 10 个 Contract / ToolExecutor / Ground Truth isolation）
- T05 确定性调查编排运行时（已完成：Runtime / Planner / 状态机 / retry / budget / trajectory / T06 handoff）
- 后续：Tool Call 编排与 Agent（LangGraph）
- 后续：Evidence 提炼与 Evidence Store
- 后续：RAG 与 MCP 集成
- 后续：证据化推理与事件调查报告生成
- 后续：评测体系与前端界面
