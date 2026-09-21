"""Investigation planning contracts: what the agent intends to do and why."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import (
    AlertId,
    EvidenceIdList,
    IncidentId,
    NonEmptyStr,
    PlanId,
    StepId,
    ToolCallIdList,
    UtcDatetime,
)


class InvestigationStepStatus(StrEnum):
    """Lifecycle state of a single investigation step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class InvestigationStep(BaseModel):
    """One planned action of an investigation plan.

    Tool calls and evidence produced while executing the step are referenced by
    ID so the plan stays a plan and not a result container.
    """

    step_id: StepId
    order: int = Field(ge=1)
    action: NonEmptyStr
    rationale: NonEmptyStr
    suggested_tool: str | None = None
    status: InvestigationStepStatus
    tool_call_ids: ToolCallIdList = Field(default_factory=list)
    evidence_ids: EvidenceIdList = Field(default_factory=list)
    started_at: UtcDatetime | None = None
    completed_at: UtcDatetime | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _validate_lifecycle(self) -> "InvestigationStep":
        if self.status is InvestigationStepStatus.RUNNING and self.started_at is None:
            raise ValueError("started_at is required when status is 'running'")

        if self.status is InvestigationStepStatus.COMPLETED:
            if self.started_at is None or self.completed_at is None:
                raise ValueError(
                    "started_at and completed_at are required when status is 'completed'"
                )

        if self.status is InvestigationStepStatus.FAILED and not (
            self.error and self.error.strip()
        ):
            raise ValueError("error is required when status is 'failed'")

        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise ValueError("completed_at must not be earlier than started_at")

        return self


class InvestigationPlan(BaseModel):
    """Ordered set of steps the agent intends to execute for one alert."""

    plan_id: PlanId
    incident_id: IncidentId
    alert_id: AlertId
    objective: NonEmptyStr
    steps: list[InvestigationStep] = Field(min_length=1)
    created_at: UtcDatetime

    @model_validator(mode="after")
    def _validate_step_order(self) -> "InvestigationPlan":
        orders = [step.order for step in self.steps]
        if len(orders) != len(set(orders)):
            raise ValueError("step 'order' values must be unique within a plan")
        return self
