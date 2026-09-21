# ThreatHunter Agent

一个自主网络安全调查 Agent：未来根据安全告警自主制定调查计划、调用安全工具、收集证据并生成事件调查报告。

## 当前开发状态

当前完成 **T01：项目骨架与工程环境初始化**、**T02：核心领域 Schema 与数据契约** 与
**T03：安全调查 Benchmark V1**。

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

尚未实现（属于后续 Task）：Agent 编排、LangGraph、Tool Calling、RAG、MCP、
LLM 调用、真实安全工具、运行时 IOC / ATT&CK 分析（当前只有静态知识数据）、
Evaluation metric 算法、数据库业务表、前端界面。

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
  agents/       Agent 相关代码（后续 Task）
  graph/        编排图（后续 Task）
  tools/        安全工具集成（后续 Task）
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
tests/          pytest 测试（tests/schemas 领域契约、tests/benchmark 数据集测试）
```

## Roadmap

- T01 项目骨架与工程环境初始化（已完成）
- T02 核心领域 Schema 与数据契约（已完成）
- T03 安全调查 Benchmark V1（已完成：8 Case / telemetry / 共享知识 / Ground Truth / Loader / Dataset Validation）
- 后续：告警数据模型与持久化
- 后续：Agent 编排（LangGraph）与 Tool Calling
- 后续：RAG 与 MCP 集成
- 后续：证据化推理与事件调查报告生成
- 后续：评测体系与前端界面
