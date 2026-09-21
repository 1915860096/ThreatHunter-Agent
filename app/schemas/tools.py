"""Tool invocation contracts: what was called, and what came back."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import (
    IncidentId,
    NonEmptyStr,
    StepId,
    ToolCallId,
    ToolResultId,
    UtcDatetime,
)


class ToolCallStatus(StrEnum):
    """Lifecycle state of a tool call."""

    REQUESTED = "requested"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ToolCall(BaseModel):
    """A request to execute one security tool, issued while running a step."""

    tool_call_id: ToolCallId
    incident_id: IncidentId
    step_id: StepId
    tool_name: NonEmptyStr
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str | None = None
    status: ToolCallStatus
    requested_at: UtcDatetime
    started_at: UtcDatetime | None = None
    completed_at: UtcDatetime | None = None

    @model_validator(mode="after")
    def _validate_chronology(self) -> "ToolCall":
        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise ValueError("completed_at must not be earlier than started_at")
        return self


class ToolResult(BaseModel):
    """The raw structured return value of a tool execution.

    A tool result is *not* evidence: it is whatever the tool reported, and it is
    kept verbatim in ``data`` so that evidence extraction stays traceable. See
    :mod:`app.schemas.evidence` for the normalised counterpart.
    """

    tool_result_id: ToolResultId
    tool_call_id: ToolCallId
    tool_name: NonEmptyStr
    success: bool
    data: dict[str, Any] | list[Any] | None = None
    error: str | None = None
    latency_ms: int = Field(ge=0)
    returned_at: UtcDatetime

    @model_validator(mode="after")
    def _validate_error_consistency(self) -> "ToolResult":
        if self.success:
            if self.error is not None:
                raise ValueError("error must be None when success is True")
        elif not (self.error and self.error.strip()):
            raise ValueError("error is required when success is False")
        return self
