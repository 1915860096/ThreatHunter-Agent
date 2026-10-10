"""Deterministic investigation orchestration runtime (T05).

The runtime drives one alert through the investigation lifecycle:

    SecurityAlert -> InvestigationPlan -> InvestigationStep -> PlannerDecision
    -> ToolCall -> ToolExecutor -> ToolResult -> step completion -> InvestigationRun

It is framework-agnostic: no LangGraph, no LLM, no prompt, no evidence layer.
A future orchestration framework can only wrap this runtime as an adapter.

Boundaries kept by this package:

* the planner is decoupled through protocols and only returns
  :class:`~app.runtime.contracts.PlannerDecision`; it never executes tools;
* the runtime owns the incident, tool-call and step lifecycles, retries,
  budget, trajectory and in-memory state;
* tools stay behind the T04 ``ToolExecutor`` contract, which is never modified;
* no dataset loader and no ground truth is reachable from here.
"""

from app.runtime.budget import InvestigationBudget
from app.runtime.contracts import (
    InvestigationRun,
    InvestigationRuntimeState,
    PlannerAction,
    PlannerDecision,
    PlanningContext,
    RuntimeStatus,
    StopReason,
    TrajectoryEvent,
    TrajectoryEventType,
)
from app.runtime.ids import IdGenerator, SequentialIdGenerator
from app.runtime.retry import RetryPolicy, ToolFailureKind, classify_tool_failure
from app.runtime.runtime import InvestigationRuntime
from app.runtime.store import (
    InMemoryRuntimeStore,
    RuntimeStateNotFoundError,
    RuntimeStore,
)
from app.runtime.trajectory import TrajectoryRecorder, sanitize_details

__all__ = [
    "IdGenerator",
    "InMemoryRuntimeStore",
    "InvestigationBudget",
    "InvestigationRun",
    "InvestigationRuntime",
    "InvestigationRuntimeState",
    "PlannerAction",
    "PlannerDecision",
    "PlanningContext",
    "RetryPolicy",
    "RuntimeStateNotFoundError",
    "RuntimeStatus",
    "RuntimeStore",
    "SequentialIdGenerator",
    "StopReason",
    "ToolFailureKind",
    "TrajectoryEvent",
    "TrajectoryEventType",
    "TrajectoryRecorder",
    "classify_tool_failure",
    "sanitize_details",
]
