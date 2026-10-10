"""Investigation budget: the deterministic limits a run may not exceed."""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.runtime.contracts import StopReason


class InvestigationBudget(BaseModel):
    """Hard limits of one investigation run.

    All limits are ``>= 1``. The runtime checks them *before* creating a new
    tool call (and before starting a new step), so a run may execute exactly
    ``max_tool_calls`` calls in total and exactly ``max_tool_calls_per_step``
    calls per step.
    """

    max_steps: int = Field(default=8, ge=1)
    max_tool_calls: int = Field(default=20, ge=1)
    max_tool_calls_per_step: int = Field(default=5, ge=1)
    max_failures: int = Field(default=5, ge=1)

    def stop_reason_for_step_start(self, *, steps_started: int) -> StopReason | None:
        """Return the reason that blocks starting one more step, if any."""
        if steps_started >= self.max_steps:
            return StopReason.MAX_STEPS_EXCEEDED
        return None

    def stop_reason_for_tool_call(
        self, *, total_tool_calls: int, calls_in_step: int
    ) -> StopReason | None:
        """Return the reason that blocks one more tool call, if any."""
        if total_tool_calls >= self.max_tool_calls:
            return StopReason.MAX_TOOL_CALLS_EXCEEDED
        if calls_in_step >= self.max_tool_calls_per_step:
            return StopReason.MAX_TOOL_CALLS_PER_STEP_EXCEEDED
        return None

    def stop_reason_for_failures(self, *, total_tool_failures: int) -> StopReason | None:
        """Return the reason that blocks further work after too many failures."""
        if total_tool_failures >= self.max_failures:
            return StopReason.TOOL_FAILURE_LIMIT
        return None
