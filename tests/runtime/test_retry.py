"""Tests for the retry policy and tool-failure classification."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.runtime import RetryPolicy, ToolFailureKind, classify_tool_failure


def test_retry_policy_defaults() -> None:
    policy = RetryPolicy()

    assert policy.max_attempts_per_step == 2
    assert policy.retry_tool_errors is True
    assert policy.retry_invalid_arguments is False


@pytest.mark.parametrize("attempts", [0, -1])
def test_retry_policy_requires_positive_attempts(attempts: int) -> None:
    with pytest.raises(ValidationError):
        RetryPolicy(max_attempts_per_step=attempts)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        ("invalid arguments for tool 'search_cti': limit: too small", ToolFailureKind.INVALID_ARGUMENTS),
        ("unknown tool 'nope'; supported tools: search_cti", ToolFailureKind.UNKNOWN_TOOL),
        ("tool 'search_cti' failed: case CASE-999 not found", ToolFailureKind.EXECUTION_ERROR),
        (None, ToolFailureKind.EXECUTION_ERROR),
        ("", ToolFailureKind.EXECUTION_ERROR),
    ],
)
def test_failure_classification(error: str | None, expected: ToolFailureKind) -> None:
    assert classify_tool_failure(error) is expected


def test_execution_errors_are_retried_within_the_attempt_budget() -> None:
    policy = RetryPolicy(max_attempts_per_step=2)

    assert policy.should_retry(ToolFailureKind.EXECUTION_ERROR, attempts_in_step=1) is True
    assert policy.should_retry(ToolFailureKind.EXECUTION_ERROR, attempts_in_step=2) is False
    assert policy.should_retry(ToolFailureKind.EXECUTION_ERROR, attempts_in_step=3) is False


def test_invalid_arguments_are_not_retried_by_default() -> None:
    policy = RetryPolicy()

    assert policy.should_retry(ToolFailureKind.INVALID_ARGUMENTS, attempts_in_step=1) is False


def test_invalid_arguments_can_be_retried_when_configured() -> None:
    policy = RetryPolicy(max_attempts_per_step=3, retry_invalid_arguments=True)

    assert policy.should_retry(ToolFailureKind.INVALID_ARGUMENTS, attempts_in_step=1) is True
    assert policy.should_retry(ToolFailureKind.INVALID_ARGUMENTS, attempts_in_step=3) is False


def test_unknown_tool_is_never_retried() -> None:
    policy = RetryPolicy(max_attempts_per_step=5, retry_tool_errors=True, retry_invalid_arguments=True)

    assert policy.should_retry(ToolFailureKind.UNKNOWN_TOOL, attempts_in_step=1) is False


def test_tool_error_retry_can_be_disabled() -> None:
    policy = RetryPolicy(retry_tool_errors=False)

    assert policy.should_retry(ToolFailureKind.EXECUTION_ERROR, attempts_in_step=1) is False
