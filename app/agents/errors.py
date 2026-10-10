"""Planner-side error types for T07.

These errors are raised by the LLM planner and are caught by the T05 runtime,
which reports any planner exception as ``StopReason.planner_failed``. T07 keeps
its own, more specific failure reason (see
``LLMPlanner.last_failure_reason``) because the frozen T05 enums are not
extended for LLM-specific reasons.
"""

from __future__ import annotations


class PlannerError(RuntimeError):
    """A planner could not produce a decision for the runtime."""


class LLMBudgetExhausted(PlannerError):
    """The model request budget of a run was exhausted before a request."""


class PlannerValidationError(PlannerError):
    """A model response could not be turned into a valid PlannerDecision."""
