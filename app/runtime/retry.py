"""Retry policy and tool-failure classification for the runtime."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

# T04 ``ToolExecutor`` reports failures as ToolResult.error strings carrying
# these documented prefixes; classification only reads that vocabulary.
INVALID_ARGUMENTS_PREFIX = "invalid arguments for tool"
UNKNOWN_TOOL_PREFIX = "unknown tool"


class ToolFailureKind(StrEnum):
    """Classification of a failed ``ToolResult``."""

    INVALID_ARGUMENTS = "invalid_arguments"
    UNKNOWN_TOOL = "unknown_tool"
    EXECUTION_ERROR = "execution_error"


def classify_tool_failure(error: str | None) -> ToolFailureKind:
    """Classify a failed tool result by its ``error`` message.

    Unrecognised or missing messages count as recoverable execution errors.
    """
    text = (error or "").strip().lower()
    if text.startswith(INVALID_ARGUMENTS_PREFIX):
        return ToolFailureKind.INVALID_ARGUMENTS
    if text.startswith(UNKNOWN_TOOL_PREFIX):
        return ToolFailureKind.UNKNOWN_TOOL
    return ToolFailureKind.EXECUTION_ERROR


class RetryPolicy(BaseModel):
    """Decides whether a failed tool call is retried.

    A retry always produces a *new* ``ToolCall`` with a new id: an existing call
    is never modified and re-executed.
    """

    max_attempts_per_step: int = Field(default=2, ge=1)
    retry_tool_errors: bool = True
    retry_invalid_arguments: bool = False

    def should_retry(self, failure: ToolFailureKind, *, attempts_in_step: int) -> bool:
        """Return whether another attempt is allowed for the failed call.

        ``attempts_in_step`` counts the attempts already used by the current
        planned tool call, including the one that just failed.
        """
        if attempts_in_step >= self.max_attempts_per_step:
            return False
        if failure is ToolFailureKind.UNKNOWN_TOOL:
            return False
        if failure is ToolFailureKind.INVALID_ARGUMENTS:
            return self.retry_invalid_arguments
        return self.retry_tool_errors
