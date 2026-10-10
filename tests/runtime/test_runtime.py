"""Tests for the orchestration runtime: lifecycles, retries, budget, failures."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from app.runtime import (
    InvestigationBudget,
    InvestigationRuntime,
    InMemoryRuntimeStore,
    PlannerAction,
    RetryPolicy,
    RuntimeStatus,
    StopReason,
    TrajectoryEventType,
)
from app.schemas.investigation import InvestigationStepStatus
from app.schemas.tools import ToolCall, ToolCallStatus, ToolResult
from tests.runtime.conftest import (
    CASE_ID,
    ExplodingExecutor,
    ScriptedPlanner,
    StubExecutor,
    TickingClock,
    call_tool,
    complete_step,
    fail_step,
    plan_factory,
    step_factory,
)

EXECUTION_ERROR = "tool 'search_endpoint_events' failed: dataset unavailable"
INVALID_ARGUMENTS_ERROR = "invalid arguments for tool 'search_endpoint_events': limit: too small"
UNKNOWN_TOOL_ERROR = "unknown tool 'nope'; supported tools: search_endpoint_events"
FIXED_RETURNED_AT = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)


class RaisingAfterExecutor:
    """Executor double returning successes, then raising on the next call."""

    def __init__(self, successes: int) -> None:
        self._remaining = successes
        self.calls = 0

    def execute(self, tool_call: ToolCall) -> ToolResult:
        self.calls += 1
        if self._remaining <= 0:
            raise RuntimeError("executor raised after earlier successes")
        self._remaining -= 1
        return ToolResult(
            tool_result_id=f"TR-{self.calls:04d}",
            tool_call_id=tool_call.tool_call_id,
            tool_name=tool_call.tool_name,
            success=True,
            data={"scripted": True},
            latency_ms=self.calls,
            returned_at=FIXED_RETURNED_AT,
        )


def test_successful_single_step_run_completes(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)]))

    run = runtime.run(alert)

    assert run.status is RuntimeStatus.COMPLETED
    assert run.stop_reason is StopReason.COMPLETED
    assert run.incident_id == "INC-000001"
    assert run.plan is not None
    assert run.plan.incident_id == run.incident_id
    assert len(run.tool_calls) == 1
    assert len(run.tool_results) == 1


def test_step_lifecycle_pending_running_completed(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)]))

    run = runtime.run(alert)

    step = run.plan.steps[0]
    assert step.status is InvestigationStepStatus.COMPLETED
    assert step.started_at is not None
    assert step.completed_at is not None
    assert step.completed_at >= step.started_at
    assert step.error is None


def test_tool_call_lifecycle_requested_running_succeeded(
    runtime_factory: Any, alert: Any
) -> None:
    stub = StubExecutor([(True, None)])
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=stub)

    run = runtime.run(alert)

    executed_call = stub.calls[0]
    # The runtime flips the call to ``running`` right before execution.
    assert executed_call.status is ToolCallStatus.RUNNING
    assert executed_call.started_at is not None
    assert executed_call.requested_at <= executed_call.started_at

    final_call = run.tool_calls[0]
    assert final_call.status is ToolCallStatus.SUCCEEDED
    assert final_call.started_at is not None
    assert final_call.completed_at is not None
    assert final_call.completed_at >= final_call.started_at

    lifecycle = [
        event.event_type
        for event in run.trajectory
        if event.tool_call_id == final_call.tool_call_id
    ]
    assert lifecycle == [
        TrajectoryEventType.TOOL_CALL_CREATED,
        TrajectoryEventType.TOOL_STARTED,
        TrajectoryEventType.TOOL_SUCCEEDED,
    ]


def test_tool_call_lifecycle_requested_running_failed(runtime_factory: Any, alert: Any) -> None:
    stub = StubExecutor([(False, EXECUTION_ERROR)])
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(
        planner, executor=stub, retry_policy=RetryPolicy(max_attempts_per_step=1)
    )

    run = runtime.run(alert)

    assert run.tool_calls[0].status is ToolCallStatus.FAILED
    assert run.tool_calls[0].completed_at is not None
    assert run.tool_results[0].success is False


def test_one_step_can_issue_multiple_tool_calls(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(
        decisions=[
            call_tool(arguments={"case_id": CASE_ID, "process_name": "powershell.exe"}),
            call_tool(arguments={"case_id": CASE_ID, "event_types": ["process_creation"]}),
            call_tool(tool_name="search_cti", arguments={"query": "powershell"}),
            complete_step(),
        ]
    )
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)] * 3))

    run = runtime.run(alert)

    assert len(run.tool_calls) == 3
    assert [call.step_id for call in run.tool_calls] == ["STEP-000001"] * 3
    assert run.plan.steps[0].status is InvestigationStepStatus.COMPLETED


def test_zero_tool_call_step_completes(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([]))

    run = runtime.run(alert)

    assert run.status is RuntimeStatus.COMPLETED
    assert run.tool_calls == []
    assert run.plan.steps[0].status is InvestigationStepStatus.COMPLETED


def test_planner_fail_step_fails_the_step_and_the_run(
    runtime_factory: Any, alert: Any
) -> None:
    planner = ScriptedPlanner(decisions=[fail_step("No usable telemetry source.")])
    runtime = runtime_factory(planner, executor=StubExecutor([]))

    run = runtime.run(alert)

    assert run.status is RuntimeStatus.FAILED
    assert run.stop_reason is StopReason.STEP_FAILED
    assert run.plan.steps[0].status is InvestigationStepStatus.FAILED
    assert run.plan.steps[0].error == "No usable telemetry source."
    assert run.trajectory[-1].event_type is TrajectoryEventType.INVESTIGATION_FAILED


def test_step_failure_does_not_stop_the_remaining_steps(
    runtime_factory: Any, alert: Any
) -> None:
    plan = plan_factory(
        step_factory(step_id="STEP-000001", order=1),
        step_factory(step_id="STEP-000002", order=2),
    )
    planner = ScriptedPlanner(plan=plan, decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(False, EXECUTION_ERROR)] * 2))

    run = runtime.run(alert)

    assert run.plan.steps[0].status is InvestigationStepStatus.FAILED
    assert run.plan.steps[1].status is InvestigationStepStatus.COMPLETED
    assert run.status is RuntimeStatus.FAILED
    assert run.stop_reason is StopReason.STEP_FAILED
    assert run.trajectory[-1].details["failed_steps"] == 1


def test_retry_creates_a_new_tool_call(runtime_factory: Any, alert: Any) -> None:
    stub = StubExecutor([(False, EXECUTION_ERROR), (True, None)])
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=stub)

    run = runtime.run(alert)

    assert [call.tool_call_id for call in run.tool_calls] == ["TC-000001", "TC-000002"]
    assert run.tool_calls[0].status is ToolCallStatus.FAILED
    assert run.tool_calls[1].status is ToolCallStatus.SUCCEEDED
    assert len(stub.calls) == 2
    event_types = [event.event_type for event in run.trajectory]
    assert TrajectoryEventType.RETRY_SCHEDULED in event_types
    assert event_types.index(TrajectoryEventType.RETRY_SCHEDULED) > event_types.index(
        TrajectoryEventType.TOOL_FAILED
    )
    assert run.plan.steps[0].status is InvestigationStepStatus.COMPLETED


def test_retry_keeps_the_previous_tool_call_failed(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(
        planner, executor=StubExecutor([(False, EXECUTION_ERROR), (True, None)])
    )

    run = runtime.run(alert)

    first, second = run.tool_calls
    assert first.status is ToolCallStatus.FAILED
    assert first.completed_at is not None
    assert second.tool_call_id != first.tool_call_id
    assert second.rationale == first.rationale


def test_retries_are_bounded_by_the_policy(runtime_factory: Any, alert: Any) -> None:
    stub = StubExecutor([(False, EXECUTION_ERROR)] * 4)
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(
        planner, executor=stub, retry_policy=RetryPolicy(max_attempts_per_step=3)
    )

    run = runtime.run(alert)

    assert len(stub.calls) == 3
    assert run.trajectory[-2].details["attempts"] == 3
    assert run.status is RuntimeStatus.FAILED
    assert run.stop_reason is StopReason.STEP_FAILED


def test_invalid_arguments_are_not_retried(runtime_factory: Any, alert: Any) -> None:
    stub = StubExecutor([(False, INVALID_ARGUMENTS_ERROR), (True, None)])
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=stub)

    run = runtime.run(alert)

    assert len(run.tool_calls) == 1
    assert run.status is RuntimeStatus.FAILED
    assert run.stop_reason is StopReason.UNRECOVERABLE_TOOL_ERROR
    assert TrajectoryEventType.RETRY_SCHEDULED not in [
        event.event_type for event in run.trajectory
    ]
    assert run.plan.steps[0].status is InvestigationStepStatus.FAILED


def test_unknown_tool_is_not_retried(runtime_factory: Any, alert: Any) -> None:
    stub = StubExecutor([(False, UNKNOWN_TOOL_ERROR), (True, None)])
    planner = ScriptedPlanner(decisions=[call_tool(tool_name="nope"), complete_step()])
    runtime = runtime_factory(planner, executor=stub)

    run = runtime.run(alert)

    assert len(run.tool_calls) == 1
    assert run.status is RuntimeStatus.FAILED
    assert run.stop_reason is StopReason.UNRECOVERABLE_TOOL_ERROR


def test_max_steps_budget_stops_the_run(runtime_factory: Any, alert: Any) -> None:
    plan = plan_factory(
        step_factory(step_id="STEP-000001", order=1),
        step_factory(step_id="STEP-000002", order=2),
        step_factory(step_id="STEP-000003", order=3),
    )
    planner = ScriptedPlanner(plan=plan, decisions=[complete_step()])
    runtime = runtime_factory(
        planner,
        executor=StubExecutor([]),
        budget=InvestigationBudget(max_steps=2),
    )

    run = runtime.run(alert)

    assert run.status is RuntimeStatus.BUDGET_EXHAUSTED
    assert run.stop_reason is StopReason.MAX_STEPS_EXCEEDED
    assert run.plan.steps[2].status is InvestigationStepStatus.PENDING
    assert run.trajectory[-1].event_type is TrajectoryEventType.BUDGET_EXHAUSTED


def test_max_tool_calls_budget_stops_the_run(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(
        decisions=[call_tool(), call_tool(tool_name="search_cti", arguments={"query": "x"})]
    )
    runtime = runtime_factory(
        planner,
        executor=StubExecutor([(True, None)] * 3),
        budget=InvestigationBudget(max_tool_calls=1, max_tool_calls_per_step=5),
    )

    run = runtime.run(alert)

    assert len(run.tool_calls) == 1
    assert run.status is RuntimeStatus.BUDGET_EXHAUSTED
    assert run.stop_reason is StopReason.MAX_TOOL_CALLS_EXCEEDED


def test_max_tool_calls_per_step_budget_stops_the_run(
    runtime_factory: Any, alert: Any
) -> None:
    planner = ScriptedPlanner(
        decisions=[
            call_tool(),
            call_tool(arguments={"case_id": CASE_ID, "host": "ws-fin-014"}),
            call_tool(tool_name="search_cti", arguments={"query": "x"}),
        ]
    )
    runtime = runtime_factory(
        planner,
        executor=StubExecutor([(True, None)] * 3),
        budget=InvestigationBudget(max_tool_calls=10, max_tool_calls_per_step=2),
    )

    run = runtime.run(alert)

    assert len(run.tool_calls) == 2
    assert run.status is RuntimeStatus.BUDGET_EXHAUSTED
    assert run.stop_reason is StopReason.MAX_TOOL_CALLS_PER_STEP_EXCEEDED


def test_max_failures_budget_stops_the_run(runtime_factory: Any, alert: Any) -> None:
    plan = plan_factory(
        step_factory(step_id="STEP-000001", order=1),
        step_factory(step_id="STEP-000002", order=2),
    )
    planner = ScriptedPlanner(plan=plan, decisions=[call_tool(), call_tool()])
    runtime = runtime_factory(
        planner,
        executor=StubExecutor([(False, EXECUTION_ERROR)] * 4),
        retry_policy=RetryPolicy(max_attempts_per_step=1),
        budget=InvestigationBudget(max_failures=1),
    )

    run = runtime.run(alert)

    assert run.status is RuntimeStatus.BUDGET_EXHAUSTED
    assert run.stop_reason is StopReason.TOOL_FAILURE_LIMIT
    assert run.tool_calls[0].status is ToolCallStatus.FAILED
    assert len(run.tool_calls) == 1


def test_planner_exception_during_planning_is_contained(
    runtime_factory: Any, alert: Any
) -> None:
    planner = ScriptedPlanner(create_plan_error=RuntimeError("planner exploded: token=SECRET"))
    runtime = runtime_factory(planner, executor=StubExecutor([]))

    run = runtime.run(alert)

    assert run.status is RuntimeStatus.FAILED
    assert run.stop_reason is StopReason.PLANNER_FAILED
    assert run.plan is None
    assert run.tool_calls == []
    assert run.trajectory[-1].event_type is TrajectoryEventType.INVESTIGATION_FAILED
    assert "SECRET" not in run.model_dump_json()
    assert "Traceback" not in run.model_dump_json()


def test_planner_exception_during_decision_is_contained(
    runtime_factory: Any, alert: Any
) -> None:
    planner = ScriptedPlanner(decide_error=ValueError("decision exploded"))
    runtime = runtime_factory(planner, executor=StubExecutor([]))

    run = runtime.run(alert)

    assert run.status is RuntimeStatus.FAILED
    assert run.stop_reason is StopReason.PLANNER_FAILED
    assert run.plan is not None
    assert run.plan.steps[0].status is InvestigationStepStatus.FAILED
    assert run.plan.steps[0].error == "planner raised ValueError"


def test_executor_exception_is_contained(runtime_factory: Any, alert: Any) -> None:
    executor = ExplodingExecutor()
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=executor)

    run = runtime.run(alert)

    assert run.status is RuntimeStatus.FAILED
    assert run.stop_reason is StopReason.UNRECOVERABLE_TOOL_ERROR
    assert executor.calls == 1
    assert run.tool_calls[0].status is ToolCallStatus.FAILED
    assert "SECRET-VALUE-KEEP-OUT" not in run.model_dump_json()
    assert "Traceback" not in run.model_dump_json()
    step_failed = next(
        event for event in run.trajectory if event.event_type is TrajectoryEventType.STEP_FAILED
    )
    assert step_failed.details["error_type"] == "RuntimeError"
    assert run.trajectory[-1].details["stop_reason"] == StopReason.UNRECOVERABLE_TOOL_ERROR.value


def test_executor_exception_records_tool_failed_event(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=ExplodingExecutor())

    run = runtime.run(alert)

    failed_events = [
        event
        for event in run.trajectory
        if event.event_type is TrajectoryEventType.TOOL_FAILED
    ]
    assert len(failed_events) == 1
    event = failed_events[0]
    assert event.tool_call_id == run.tool_calls[0].tool_call_id
    assert event.step_id == run.tool_calls[0].step_id
    assert event.tool_result_id is None
    assert event.details["failure_kind"] == "executor_exception"
    assert event.details["attempt"] == 1
    assert event.details["tool_name"] == "search_endpoint_events"
    assert "error" not in event.details
    assert "traceback" not in json.dumps(event.details).lower()

    event_types = [entry.event_type for entry in run.trajectory]
    assert event_types.index(TrajectoryEventType.TOOL_STARTED) < event_types.index(
        TrajectoryEventType.TOOL_FAILED
    )
    assert event_types.index(TrajectoryEventType.TOOL_FAILED) < event_types.index(
        TrajectoryEventType.STEP_FAILED
    )


def test_executor_exception_fabricates_no_tool_result(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=ExplodingExecutor())

    run = runtime.run(alert)

    assert run.tool_results == []
    assert run.tool_calls[0].status is ToolCallStatus.FAILED
    assert all(event.tool_result_id is None for event in run.trajectory)
    assert "TR-" not in run.model_dump_json()


def test_executor_exception_counts_the_attempt(runtime_factory: Any, alert: Any) -> None:
    store = InMemoryRuntimeStore()
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=ExplodingExecutor(), store=store)

    run = runtime.run(alert)
    state = store.load_state(run.incident_id)

    assert state.total_tool_calls == 1
    assert state.total_tool_failures == 1
    assert state.step_attempts == {"STEP-000001": 1}
    assert state.tool_calls == run.tool_calls
    assert state.tool_results == []


def test_executor_exception_preserves_earlier_history(runtime_factory: Any, alert: Any) -> None:
    executor = RaisingAfterExecutor(successes=1)
    planner = ScriptedPlanner(
        decisions=[
            call_tool(),
            call_tool(tool_name="search_cti", arguments={"query": "certutil"}),
            complete_step(),
        ]
    )
    runtime = runtime_factory(planner, executor=executor)

    run = runtime.run(alert)

    assert executor.calls == 2
    assert [call.status for call in run.tool_calls] == [
        ToolCallStatus.SUCCEEDED,
        ToolCallStatus.FAILED,
    ]
    assert len(run.tool_results) == 1
    assert run.tool_results[0].success is True
    assert run.tool_results[0].tool_call_id == run.tool_calls[0].tool_call_id
    failed_event = next(
        event
        for event in run.trajectory
        if event.event_type is TrajectoryEventType.TOOL_FAILED
    )
    assert failed_event.tool_call_id == run.tool_calls[1].tool_call_id
    assert failed_event.tool_result_id is None
    assert run.stop_reason is StopReason.UNRECOVERABLE_TOOL_ERROR


def test_attempt_counting_is_consistent_across_execution_paths(
    runtime_factory: Any, alert: Any
) -> None:
    scenarios = [
        (
            "success",
            {"executor": StubExecutor([(True, None)])},
            {"calls": 1, "failures": 0, "attempts": 1, "results": 1},
        ),
        (
            "returned failure without retry",
            {
                "executor": StubExecutor([(False, EXECUTION_ERROR)]),
                "retry_policy": RetryPolicy(max_attempts_per_step=1),
            },
            {"calls": 1, "failures": 1, "attempts": 1, "results": 1},
        ),
        (
            "retry then success",
            {"executor": StubExecutor([(False, EXECUTION_ERROR), (True, None)])},
            {"calls": 2, "failures": 1, "attempts": 2, "results": 2},
        ),
        (
            "executor exception",
            {"executor": ExplodingExecutor()},
            {"calls": 1, "failures": 1, "attempts": 1, "results": 0},
        ),
    ]

    for label, overrides, expected in scenarios:
        store = InMemoryRuntimeStore()
        planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
        runtime = runtime_factory(planner, store=store, **overrides)

        run = runtime.run(alert)
        state = store.load_state(run.incident_id)

        assert state.total_tool_calls == expected["calls"], label
        assert state.total_tool_failures == expected["failures"], label
        assert state.step_attempts == {"STEP-000001": expected["attempts"]}, label
        assert len(run.tool_calls) == expected["calls"], label
        assert len(run.tool_results) == expected["results"], label


def test_tool_results_are_linked_to_their_calls(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(
        decisions=[call_tool(), call_tool(tool_name="search_cti", arguments={"query": "x"})]
    )
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)] * 2))

    run = runtime.run(alert)

    calls = {call.tool_call_id: call for call in run.tool_calls}
    assert run.tool_results
    for result in run.tool_results:
        assert result.tool_call_id in calls
        assert calls[result.tool_call_id].tool_name == result.tool_name
        assert result.tool_result_id.startswith("TR-")


def test_run_keeps_full_tool_history_for_t06(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)]))

    run = runtime.run(alert)

    call = run.tool_calls[0]
    result = run.tool_results[0]
    assert call.incident_id == run.incident_id
    assert call.step_id == run.plan.steps[0].step_id
    assert call.arguments == {"case_id": CASE_ID}
    assert result.data == {"scripted": True}
    assert run.status is RuntimeStatus.COMPLETED
    dumped = run.model_dump_json()
    assert '"evidence_id":' not in dumped
    assert "evd-" not in dumped.lower()


def test_trajectory_references_real_ids(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(False, EXECUTION_ERROR), (True, None)]))

    run = runtime.run(alert)

    step_ids = {step.step_id for step in run.plan.steps}
    call_ids = {call.tool_call_id for call in run.tool_calls}
    result_ids = {result.tool_result_id for result in run.tool_results}

    assert run.trajectory
    for event in run.trajectory:
        assert event.incident_id == run.incident_id
        if event.step_id is not None:
            assert event.step_id in step_ids
        if event.tool_call_id is not None:
            assert event.tool_call_id in call_ids
        if event.tool_result_id is not None:
            assert event.tool_result_id in result_ids
            assert event.event_type in {
                TrajectoryEventType.TOOL_SUCCEEDED,
                TrajectoryEventType.TOOL_FAILED,
            }


def test_trajectory_sequence_is_strictly_increasing(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)]))

    run = runtime.run(alert)

    sequences = [event.sequence for event in run.trajectory]
    assert sequences[0] == 1
    assert sequences == list(range(1, len(sequences) + 1))
    assert sequences == sorted(set(sequences))


def test_trajectory_contains_no_payload_or_secret(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)]))

    run = runtime.run(alert)
    forbidden_keys = {
        "items",
        "files",
        "records",
        "network_events",
        "dns_events",
        "cti_records",
        "attack_techniques",
        "data",
        "payload",
        "token",
        "secret",
        "traceback",
        "ground_truth",
        "expected_verdict",
        "key_evidence",
    }

    for event in run.trajectory:
        assert not forbidden_keys & set(event.details)
        dumped = json.dumps(event.details)
        assert "SECRET" not in dumped
        assert "Traceback" not in dumped


def test_store_receives_the_final_state(runtime_factory: Any, alert: Any, store: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)]))

    run = runtime.run(alert)
    state = store.load_state(run.incident_id)

    assert state.status is run.status
    assert state.stop_reason is run.stop_reason
    assert len(state.tool_calls) == len(run.tool_calls)
    assert len(state.tool_results) == len(run.tool_results)
    assert state.completed_at is not None
    assert state.step_attempts == {"STEP-000001": 1}


def test_incident_ids_increment_across_runs(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([]))

    first = runtime.run(alert)
    second = runtime.run(alert)

    assert (first.incident_id, second.incident_id) == ("INC-000001", "INC-000002")


def test_tool_call_ids_increment_within_a_run(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(
        decisions=[
            call_tool(),
            call_tool(tool_name="search_cti", arguments={"query": "x"}),
            complete_step(),
        ]
    )
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)] * 2))

    run = runtime.run(alert)

    assert [call.tool_call_id for call in run.tool_calls] == ["TC-000001", "TC-000002"]


def test_runs_are_deterministic_for_identical_inputs(alert: Any) -> None:
    def build_run() -> Any:
        clock = TickingClock()
        planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
        runtime = InvestigationRuntime(
            planner,
            executor=StubExecutor([(True, None)], clock=clock),
            clock=clock,
        )
        return runtime.run(alert)

    first = build_run()
    second = build_run()

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_step_attempts_are_recorded(runtime_factory: Any, alert: Any) -> None:
    store = InMemoryRuntimeStore()
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(
        planner,
        executor=StubExecutor([(False, EXECUTION_ERROR), (True, None)]),
        store=store,
    )

    run = runtime.run(alert)
    state = store.load_state(run.incident_id)

    assert state.step_attempts == {"STEP-000001": 2}
    assert state.total_tool_calls == 2
    assert state.total_tool_failures == 1


def test_planner_receives_budget_and_history(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(
        decisions=[
            call_tool(),
            complete_step(),
        ]
    )
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)]))

    runtime.run(alert)

    first_context, second_context = planner.contexts[:2]
    assert first_context.current_step.step_id == "STEP-000001"
    assert first_context.previous_tool_calls == []
    assert first_context.remaining_tool_budget == InvestigationBudget().max_tool_calls
    assert first_context.remaining_step_budget == InvestigationBudget().max_tool_calls_per_step
    assert len(second_context.previous_tool_calls) == 1
    assert len(second_context.previous_tool_results) == 1
    assert second_context.remaining_tool_budget == InvestigationBudget().max_tool_calls - 1


def test_decision_actions_reach_the_trajectory(runtime_factory: Any, alert: Any) -> None:
    planner = ScriptedPlanner(decisions=[call_tool(), complete_step()])
    runtime = runtime_factory(planner, executor=StubExecutor([(True, None)]))

    run = runtime.run(alert)
    decisions = [
        event
        for event in run.trajectory
        if event.event_type is TrajectoryEventType.PLANNER_DECISION
    ]

    assert [event.details["action"] for event in decisions] == [
        PlannerAction.CALL_TOOL.value,
        PlannerAction.COMPLETE_STEP.value,
    ]
