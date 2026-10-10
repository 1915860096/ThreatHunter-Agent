"""Tests for the runtime contracts (enums, decisions, context, state, run)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.runtime import (
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
from app.schemas.tools import ToolCall, ToolResult
from tests.runtime.conftest import (
    CASE_ID,
    START_TIME,
    complete_step,
    fail_step,
    plan_factory,
    step_factory,
)


def test_runtime_status_values() -> None:
    assert [status.value for status in RuntimeStatus] == [
        "initialized",
        "planning",
        "running",
        "completed",
        "failed",
        "budget_exhausted",
    ]


def test_planner_action_values() -> None:
    assert [action.value for action in PlannerAction] == [
        "call_tool",
        "complete_step",
        "fail_step",
    ]


def test_stop_reason_contains_required_values() -> None:
    required = {
        "completed",
        "planner_failed",
        "tool_failure_limit",
        "max_steps_exceeded",
        "max_tool_calls_exceeded",
        "max_tool_calls_per_step_exceeded",
        "unrecoverable_tool_error",
    }

    assert required <= {reason.value for reason in StopReason}


def test_trajectory_event_types_contain_required_values() -> None:
    required = {
        "investigation_started",
        "plan_created",
        "step_started",
        "planner_decision",
        "tool_call_created",
        "tool_started",
        "tool_succeeded",
        "tool_failed",
        "retry_scheduled",
        "step_completed",
        "step_failed",
        "budget_exhausted",
        "investigation_completed",
        "investigation_failed",
    }

    assert required <= {event.value for event in TrajectoryEventType}


def test_call_tool_decision_is_valid() -> None:
    decision = PlannerDecision(
        action=PlannerAction.CALL_TOOL,
        tool_name="search_endpoint_events",
        arguments={"case_id": CASE_ID},
        rationale="Query endpoint telemetry.",
    )

    assert decision.tool_name == "search_endpoint_events"
    assert decision.arguments == {"case_id": CASE_ID}


@pytest.mark.parametrize("tool_name", [None, "", "   "])
def test_call_tool_requires_tool_name(tool_name: str | None) -> None:
    with pytest.raises(ValidationError, match="tool_name is required"):
        PlannerDecision(
            action=PlannerAction.CALL_TOOL,
            tool_name=tool_name,
            arguments={"case_id": CASE_ID},
            rationale="Query endpoint telemetry.",
        )


def test_call_tool_requires_arguments() -> None:
    with pytest.raises(ValidationError, match="arguments is required"):
        PlannerDecision(
            action=PlannerAction.CALL_TOOL,
            tool_name="search_endpoint_events",
            rationale="Query endpoint telemetry.",
        )


def test_complete_step_rejects_tool_payload() -> None:
    with pytest.raises(ValidationError, match="tool_name must be None"):
        PlannerDecision(
            action=PlannerAction.COMPLETE_STEP,
            tool_name="search_endpoint_events",
            rationale="Done.",
        )


def test_fail_step_rejects_arguments() -> None:
    with pytest.raises(ValidationError, match="arguments must be None"):
        PlannerDecision(
            action=PlannerAction.FAIL_STEP,
            arguments={"case_id": CASE_ID},
            rationale="Cannot continue.",
        )


def test_decisions_require_rationale() -> None:
    with pytest.raises(ValidationError):
        PlannerDecision(action=PlannerAction.COMPLETE_STEP, rationale="  ")


def test_planning_context_defaults(alert: object) -> None:
    context = PlanningContext(
        alert=alert,
        plan=plan_factory(),
        current_step=step_factory(),
    )

    assert context.previous_tool_calls == []
    assert context.previous_tool_results == []
    assert context.remaining_tool_budget == 0
    assert context.remaining_step_budget == 0


def test_planning_context_rejects_negative_budget(alert: object) -> None:
    with pytest.raises(ValidationError):
        PlanningContext(
            alert=alert,
            plan=plan_factory(),
            current_step=step_factory(),
            remaining_tool_budget=-1,
        )


def test_planning_context_carries_tool_history(alert: object) -> None:
    call = ToolCall(
        tool_call_id="TC-000001",
        incident_id="INC-000001",
        step_id="STEP-000001",
        tool_name="search_cti",
        status="succeeded",
        requested_at=START_TIME,
    )
    result = ToolResult(
        tool_result_id="TR-0001",
        tool_call_id="TC-000001",
        tool_name="search_cti",
        success=True,
        data={"cti_count": 1},
        latency_ms=1,
        returned_at=START_TIME,
    )

    context = PlanningContext(
        alert=alert,
        plan=plan_factory(),
        current_step=step_factory(),
        previous_tool_calls=[call],
        previous_tool_results=[result],
        remaining_tool_budget=5,
        remaining_step_budget=2,
    )

    assert context.previous_tool_calls[0].tool_call_id == "TC-000001"
    assert context.previous_tool_results[0].tool_result_id == "TR-0001"


def test_trajectory_event_requires_sequence_and_aware_timestamp(alert: object) -> None:
    with pytest.raises(ValidationError):
        TrajectoryEvent(
            sequence=0,
            timestamp=START_TIME,
            event_type=TrajectoryEventType.PLAN_CREATED,
            incident_id="INC-000001",
        )

    with pytest.raises(ValidationError):
        TrajectoryEvent(
            sequence=1,
            timestamp="2026-06-01T00:00:00",
            event_type=TrajectoryEventType.PLAN_CREATED,
            incident_id="INC-000001",
        )


def test_runtime_state_defaults_and_independent_collections(alert: object) -> None:
    first = InvestigationRuntimeState(
        incident_id="INC-000001", alert=alert, started_at=START_TIME, updated_at=START_TIME
    )
    second = InvestigationRuntimeState(
        incident_id="INC-000002", alert=alert, started_at=START_TIME, updated_at=START_TIME
    )

    assert first.status is RuntimeStatus.INITIALIZED
    assert first.plan is None
    assert first.current_step_id is None
    assert first.stop_reason is None
    assert first.completed_at is None
    assert first.total_tool_calls == 0
    assert first.total_tool_failures == 0

    first.step_attempts["STEP-000001"] = 2
    first.tool_calls.append(
        ToolCall(
            tool_call_id="TC-000001",
            incident_id="INC-000001",
            step_id="STEP-000001",
            tool_name="search_cti",
            status="requested",
            requested_at=START_TIME,
        )
    )

    assert second.step_attempts == {}
    assert second.tool_calls == []


def test_investigation_run_requires_increasing_trajectory(alert: object) -> None:
    def event(sequence: int) -> TrajectoryEvent:
        return TrajectoryEvent(
            sequence=sequence,
            timestamp=START_TIME,
            event_type=TrajectoryEventType.INVESTIGATION_COMPLETED,
            incident_id="INC-000001",
        )

    run = InvestigationRun(
        incident_id="INC-000001",
        alert=alert,
        plan=plan_factory(),
        trajectory=[event(1), event(2)],
        status=RuntimeStatus.COMPLETED,
        stop_reason=StopReason.COMPLETED,
        started_at=START_TIME,
        completed_at=START_TIME,
    )

    assert [entry.sequence for entry in run.trajectory] == [1, 2]

    with pytest.raises(ValidationError, match="sequence numbers must be unique and increasing"):
        InvestigationRun(
            incident_id="INC-000001",
            alert=alert,
            plan=plan_factory(),
            trajectory=[event(2), event(1)],
            status=RuntimeStatus.COMPLETED,
            stop_reason=StopReason.COMPLETED,
            started_at=START_TIME,
            completed_at=START_TIME,
        )


def test_investigation_run_allows_missing_plan(alert: object) -> None:
    run = InvestigationRun(
        incident_id="INC-000001",
        alert=alert,
        status=RuntimeStatus.FAILED,
        stop_reason=StopReason.PLANNER_FAILED,
        started_at=START_TIME,
        completed_at=START_TIME,
    )

    assert run.plan is None
    assert run.tool_calls == []
    assert run.tool_results == []


def test_decision_helpers_build_expected_actions() -> None:
    assert complete_step().action is PlannerAction.COMPLETE_STEP
    assert fail_step().action is PlannerAction.FAIL_STEP
