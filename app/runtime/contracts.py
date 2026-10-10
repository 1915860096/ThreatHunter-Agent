"""Runtime contracts for T05: enums, decisions, state, trajectory and run.

All timestamps follow the project UTC-aware convention and all mutable
defaults use ``default_factory``. ``TrajectoryEvent.sequence`` is the
authoritative ordering of a run; timestamps are informational only.

``InvestigationRun`` is the formal T05 -> T06 handoff contract: it keeps every
``ToolCall`` and ``ToolResult`` (including payloads) so a later evidence stage
can rebuild ``ToolCall -> ToolResult -> Evidence -> EvidenceProvenance``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.schemas.alert import SecurityAlert
from app.schemas.common import (
    IncidentId,
    NonEmptyStr,
    StepId,
    ToolCallId,
    ToolResultId,
    UtcDatetime,
)
from app.schemas.investigation import InvestigationPlan, InvestigationStep
from app.schemas.tools import ToolCall, ToolResult


class RuntimeStatus(StrEnum):
    """Lifecycle status of one investigation run."""

    INITIALIZED = "initialized"
    PLANNING = "planning"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BUDGET_EXHAUSTED = "budget_exhausted"


class PlannerAction(StrEnum):
    """What the planner asks the runtime to do next for the current step."""

    CALL_TOOL = "call_tool"
    COMPLETE_STEP = "complete_step"
    FAIL_STEP = "fail_step"


class StopReason(StrEnum):
    """Why a run stopped.

    The first seven values are the required T05 reasons; ``STEP_FAILED``
    describes "orchestration finished, but at least one step failed" and
    ``RUNTIME_ERROR`` an internal, unexpected failure that was contained.
    """

    COMPLETED = "completed"
    PLANNER_FAILED = "planner_failed"
    TOOL_FAILURE_LIMIT = "tool_failure_limit"
    MAX_STEPS_EXCEEDED = "max_steps_exceeded"
    MAX_TOOL_CALLS_EXCEEDED = "max_tool_calls_exceeded"
    MAX_TOOL_CALLS_PER_STEP_EXCEEDED = "max_tool_calls_per_step_exceeded"
    UNRECOVERABLE_TOOL_ERROR = "unrecoverable_tool_error"
    STEP_FAILED = "step_failed"
    RUNTIME_ERROR = "runtime_error"


class TrajectoryEventType(StrEnum):
    """Append-only trajectory vocabulary of one run."""

    INVESTIGATION_STARTED = "investigation_started"
    PLAN_CREATED = "plan_created"
    STEP_STARTED = "step_started"
    PLANNER_DECISION = "planner_decision"
    TOOL_CALL_CREATED = "tool_call_created"
    TOOL_STARTED = "tool_started"
    TOOL_SUCCEEDED = "tool_succeeded"
    TOOL_FAILED = "tool_failed"
    RETRY_SCHEDULED = "retry_scheduled"
    STEP_COMPLETED = "step_completed"
    STEP_FAILED = "step_failed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INVESTIGATION_COMPLETED = "investigation_completed"
    INVESTIGATION_FAILED = "investigation_failed"


class PlannerDecision(BaseModel):
    """One planner decision for the current step.

    ``call_tool`` must carry a tool name and arguments; ``complete_step`` and
    ``fail_step`` must carry neither.
    """

    action: PlannerAction
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    rationale: NonEmptyStr

    @model_validator(mode="after")
    def _validate_action_payload(self) -> "PlannerDecision":
        if self.action is PlannerAction.CALL_TOOL:
            if self.tool_name is None or not self.tool_name.strip():
                raise ValueError("tool_name is required when action is 'call_tool'")
            if self.arguments is None:
                raise ValueError("arguments is required when action is 'call_tool'")
            return self

        if self.tool_name is not None:
            raise ValueError(f"tool_name must be None when action is '{self.action.value}'")
        if self.arguments is not None:
            raise ValueError(f"arguments must be None when action is '{self.action.value}'")
        return self


class PlanningContext(BaseModel):
    """Everything a planner may look at - and nothing more.

    The context carries no loader, no dataset path and no ground truth: the
    planner sees the alert, the plan, the current step, the tool history of the
    run so far and the remaining budgets.
    """

    alert: SecurityAlert
    plan: InvestigationPlan
    current_step: InvestigationStep
    previous_tool_calls: list[ToolCall] = Field(default_factory=list)
    previous_tool_results: list[ToolResult] = Field(default_factory=list)
    remaining_tool_budget: int = Field(default=0, ge=0)
    remaining_step_budget: int = Field(default=0, ge=0)


class TrajectoryEvent(BaseModel):
    """One point in the investigation trajectory.

    ``details`` must stay small and non-sensitive: it carries scalars and lists
    of scalars only, never secrets, tracebacks, ground truth or a full
    ``ToolResult`` payload (results are referenced through ``tool_result_id``).
    """

    sequence: int = Field(ge=1)
    timestamp: UtcDatetime
    event_type: TrajectoryEventType
    incident_id: IncidentId
    step_id: StepId | None = None
    tool_call_id: ToolCallId | None = None
    tool_result_id: ToolResultId | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class InvestigationRuntimeState(BaseModel):
    """Mutable runtime state of one incident.

    ``plan`` is ``None`` only before the planner produced one. ``step_attempts``
    records, per step id, the highest number of attempts used by any single
    planned tool call of that step.
    """

    incident_id: IncidentId
    alert: SecurityAlert
    plan: InvestigationPlan | None = None
    current_step_id: StepId | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    step_attempts: dict[str, int] = Field(default_factory=dict)
    total_tool_calls: int = Field(default=0, ge=0)
    total_tool_failures: int = Field(default=0, ge=0)
    status: RuntimeStatus = RuntimeStatus.INITIALIZED
    started_at: UtcDatetime
    updated_at: UtcDatetime
    completed_at: UtcDatetime | None = None
    stop_reason: StopReason | None = None


class InvestigationRun(BaseModel):
    """Final T05 output and the handoff contract for T06.

    The run keeps the complete tool history (every ``ToolCall`` and its
    ``ToolResult`` payload) plus the ordered trajectory. ``plan`` is ``None``
    only when the planner failed before producing one. T05 creates no evidence:
    T06 can derive evidence and provenance from the retained ``tool_call_id`` /
    ``tool_result_id`` pairs.
    """

    incident_id: IncidentId
    alert: SecurityAlert
    plan: InvestigationPlan | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    trajectory: list[TrajectoryEvent] = Field(default_factory=list)
    status: RuntimeStatus
    stop_reason: StopReason
    started_at: UtcDatetime
    completed_at: UtcDatetime

    @model_validator(mode="after")
    def _validate_trajectory_order(self) -> "InvestigationRun":
        sequences = [event.sequence for event in self.trajectory]
        if len(set(sequences)) != len(sequences) or sequences != sorted(sequences):
            raise ValueError("trajectory sequence numbers must be unique and increasing")
        return self
