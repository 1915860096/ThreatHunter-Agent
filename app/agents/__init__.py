"""Investigation planners (T05 + T07).

The planner is the only decision-making component of the orchestration
runtime, and it is deliberately decoupled from it:

* :class:`~app.agents.planner.InvestigationPlanner` is the protocol the runtime
  depends on;
* :class:`~app.agents.deterministic.DeterministicPlanner` is the rule-based
  planner used to exercise orchestration;
* :class:`~app.agents.llm_planner.LLMPlanner` adds a model-driven planner (T07)
  that keeps the deterministic five-phase skeleton, receives a sanitized
  :class:`~app.agents.context.AgentContext` and only ever returns validated
  ``PlannerDecision`` values - the T05 runtime still creates every ToolCall and
  the T04 executor still runs every tool.

A planner returns :class:`~app.runtime.contracts.PlannerDecision` values and
never executes a tool, never imports a dataset loader and never sees ground
truth.
"""

from app.agents.context import (
    AgentAlertView,
    AgentContext,
    AgentContextBuilder,
    AgentQueryHistoryEntry,
    AgentStepView,
    AgentToolCallView,
    AgentToolConstraint,
    AgentToolResultView,
    sanitize_text,
)
from app.agents.decision_trace import (
    AgentDecisionTrace,
    AgentDecisionTraceRecorder,
    correlate_trace_with_run,
)
from app.agents.deterministic import PLACEHOLDER_INCIDENT_ID, DeterministicPlanner
from app.agents.errors import (
    LLMBudgetExhausted,
    PlannerError,
    PlannerValidationError,
)
from app.agents.llm_budget import LLMBudget, LLMBudgetTracker
from app.agents.llm_client import (
    LLMAuthenticationError,
    LLMClient,
    LLMClientConfig,
    LLMClientError,
    LLMCompletion,
    LLMConfigurationError,
    LLMHTTPError,
    LLMResponseError,
    LLMTimeoutError,
    OpenAICompatibleLLMClient,
)
from app.agents.llm_planner import (
    ALLOWED_TOOLS_BY_STEP_ORDER,
    SYSTEM_PROMPT,
    LLMPlanner,
)
from app.agents.planner import InvestigationPlanner

__all__ = [
    "ALLOWED_TOOLS_BY_STEP_ORDER",
    "SYSTEM_PROMPT",
    "AgentAlertView",
    "AgentContext",
    "AgentContextBuilder",
    "AgentDecisionTrace",
    "AgentDecisionTraceRecorder",
    "AgentQueryHistoryEntry",
    "AgentStepView",
    "AgentToolCallView",
    "AgentToolConstraint",
    "AgentToolResultView",
    "PLACEHOLDER_INCIDENT_ID",
    "DeterministicPlanner",
    "InvestigationPlanner",
    "LLMAuthenticationError",
    "LLMBudget",
    "LLMBudgetExhausted",
    "LLMBudgetTracker",
    "LLMClient",
    "LLMClientConfig",
    "LLMClientError",
    "LLMCompletion",
    "LLMConfigurationError",
    "LLMHTTPError",
    "LLMPlanner",
    "LLMResponseError",
    "LLMTimeoutError",
    "OpenAICompatibleLLMClient",
    "PlannerError",
    "PlannerValidationError",
    "correlate_trace_with_run",
    "sanitize_text",
]
