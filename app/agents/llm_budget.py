"""Model request budget for the LLM planner (T07).

The budget is independent from the T05 tool-call budget and covers first
requests plus repair requests. It is checked *before* every request and raises
:class:`~app.agents.errors.LLMBudgetExhausted`, which the T05 runtime reports as
``StopReason.planner_failed`` (the frozen T05 enums are not extended).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.agents.errors import LLMBudgetExhausted

DEFAULT_MAX_LLM_REQUESTS_PER_RUN: int = 24
DEFAULT_MAX_REPAIR_ATTEMPTS_PER_DECISION: int = 1
DEFAULT_REQUEST_TIMEOUT_SECONDS: float = 30.0


class LLMBudget(BaseModel):
    """Limits for model requests of one investigation run."""

    max_llm_requests_per_run: int = Field(
        default=DEFAULT_MAX_LLM_REQUESTS_PER_RUN, ge=1
    )
    max_repair_attempts_per_decision: int = Field(
        default=DEFAULT_MAX_REPAIR_ATTEMPTS_PER_DECISION, ge=0
    )
    request_timeout_seconds: float = Field(
        default=DEFAULT_REQUEST_TIMEOUT_SECONDS, ge=1.0
    )


class LLMBudgetTracker:
    """Counts requests for one run and refuses to exceed the budget."""

    def __init__(self, budget: LLMBudget | None = None) -> None:
        self._budget = budget or LLMBudget()
        self._used = 0

    @property
    def budget(self) -> LLMBudget:
        """The budget being tracked."""
        return self._budget

    @property
    def used(self) -> int:
        """Requests already consumed."""
        return self._used

    @property
    def remaining(self) -> int:
        """Requests still available."""
        return max(self._budget.max_llm_requests_per_run - self._used, 0)

    def reset(self) -> None:
        """Reset the counter (used when one tracker serves several runs)."""
        self._used = 0

    def consume(self) -> int:
        """Consume one request and return the new count, or raise."""
        if self._used >= self._budget.max_llm_requests_per_run:
            raise LLMBudgetExhausted(
                "LLM request budget exhausted "
                f"({self._used}/{self._budget.max_llm_requests_per_run} requests used)"
            )
        self._used += 1
        return self._used
