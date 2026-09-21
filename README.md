# ThreatHunter Agent

一个自主网络安全调查 Agent：未来根据安全告警自主制定调查计划、调用安全工具、收集证据并生成事件调查报告。

## 当前开发状态

当前完成 **T01：项目骨架与工程环境初始化** 与 **T02：核心领域 Schema 与数据契约**。

已经具备的能力：

- 可安装的 Python 项目骨架（`pyproject.toml` + 包目录结构）
- 基于 `pydantic-settings` 的配置系统（支持 `.env`）
- 基于 FastAPI 的最小应用，只暴露 `GET /health`
- PostgreSQL 16 的 Docker Compose 编排（仅数据库容器，无业务表）
- 基于 pytest + FastAPI TestClient 的冒烟测试
- Pydantic v2 领域数据契约：告警、调查计划、工具调用、证据、结论、报告（含 ID 前缀、
  时区与各类一致性校验），供后续 Dataset / Tools / Evidence Store / RAG / MCP /
  LangGraph / Agent / Evaluation 共同复用

尚未实现（属于后续 Task）：Agent 编排、LangGraph、Tool Calling、RAG、MCP、
LLM 调用、CTI / MITRE ATT&CK / IOC 分析、数据库业务表、前端界面。

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
  agents/       Agent 相关代码（后续 Task）
  graph/        编排图（后续 Task）
  tools/        安全工具集成（后续 Task）
  rag/          检索增强（后续 Task）
  mcp/          MCP 集成（后续 Task）
  evidence/     证据模型与推理（后续 Task）
  db/           持久化层（后续 Task）
  schemas/      Pydantic v2 领域数据契约
  core/         配置与核心基础设施
datasets/       本地数据集（cases 告警样本、knowledge 知识库）
evaluation/     评测脚本与结果
frontend/       前端入口（后续 Task）
scripts/        运维 / 辅助脚本
tests/          pytest 测试（tests/schemas 为领域契约测试）
```

## Roadmap

- T01 项目骨架与工程环境初始化（已完成）
- T02 核心领域 Schema 与数据契约（已完成）
- 后续：告警数据模型与持久化
- 后续：Agent 编排（LangGraph）与 Tool Calling
- 后续：RAG 与 MCP 集成
- 后续：证据化推理与事件调查报告生成
- 后续：评测体系与前端界面
