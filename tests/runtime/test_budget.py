"""Tests for the investigation budget."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.runtime import InvestigationBudget, StopReason


def test_default_budget_values() -> None:
    budget = InvestigationBudget()

    assert budget.max_steps == 8
    assert budget.max_tool_calls == 20
    assert budget.max_tool_calls_per_step == 5
    assert budget.max_failures == 5


@pytest.mark.parametrize(
    "field",
    ["max_steps", "max_tool_calls", "max_tool_calls_per_step", "max_failures"],
)
@pytest.mark.parametrize("value", [0, -1])
def test_budget_limits_must_be_at_least_one(field: str, value: int) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationBudget(**{field: value})

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_step_start_budget_is_exhausted_at_the_limit() -> None:
    budget = InvestigationBudget(max_steps=2)

    assert budget.stop_reason_for_step_start(steps_started=0) is None
    assert budget.stop_reason_for_step_start(steps_started=1) is None
    assert budget.stop_reason_for_step_start(steps_started=2) is StopReason.MAX_STEPS_EXCEEDED


def test_tool_call_budget_is_exhausted_at_the_limit() -> None:
    budget = InvestigationBudget(max_tool_calls=2, max_tool_calls_per_step=5)

    assert budget.stop_reason_for_tool_call(total_tool_calls=1, calls_in_step=1) is None
    assert (
        budget.stop_reason_for_tool_call(total_tool_calls=2, calls_in_step=2)
        is StopReason.MAX_TOOL_CALLS_EXCEEDED
    )


def test_per_step_tool_call_budget_is_exhausted_at_the_limit() -> None:
    budget = InvestigationBudget(max_tool_calls=10, max_tool_calls_per_step=2)

    assert budget.stop_reason_for_tool_call(total_tool_calls=1, calls_in_step=1) is None
    assert (
        budget.stop_reason_for_tool_call(total_tool_calls=2, calls_in_step=2)
        is StopReason.MAX_TOOL_CALLS_PER_STEP_EXCEEDED
    )


def test_total_budget_wins_over_per_step_budget() -> None:
    budget = InvestigationBudget(max_tool_calls=1, max_tool_calls_per_step=1)

    assert (
        budget.stop_reason_for_tool_call(total_tool_calls=1, calls_in_step=1)
        is StopReason.MAX_TOOL_CALLS_EXCEEDED
    )


def test_failure_budget_is_exhausted_at_the_limit() -> None:
    budget = InvestigationBudget(max_failures=3)

    assert budget.stop_reason_for_failures(total_tool_failures=2) is None
    assert (
        budget.stop_reason_for_failures(total_tool_failures=3)
        is StopReason.TOOL_FAILURE_LIMIT
    )
