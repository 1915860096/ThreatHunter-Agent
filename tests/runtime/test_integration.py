"""End-to-end runtime integration against the real T03 benchmark dataset."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from app.agents import DeterministicPlanner
from app.benchmark import BenchmarkLoader
from app.runtime import (
    InvestigationRuntime,
    PlannerAction,
    RuntimeStatus,
    SequentialIdGenerator,
    StopReason,
)
from app.schemas.investigation import InvestigationStepStatus
from app.tools import ToolExecutor
from tests.runtime.conftest import CASE_ID, TickingClock

CASE_WITH_FILE_ARTIFACT = "CASE-002"

#: Wall-clock measurements produced by the real T04 ``ToolExecutor``
#: (``time.perf_counter``). They are the only non-deterministic part of an
#: otherwise reproducible run.
VOLATILE_PERFORMANCE_FIELDS = ("latency_ms",)


def normalized_run_dump(run: Any) -> dict[str, Any]:
    """Serialise a run with wall-clock performance measurements removed.

    Only ``tool_results[*].latency_ms`` and ``trajectory[*].details.latency_ms``
    are dropped. Everything else stays exactly as produced: plan and steps,
    tool-call order, arguments and statuses, tool-result payloads, runtime
    status, stop reason and every trajectory sequence / event type / reference /
    non-performance detail.
    """
    dump = run.model_dump(mode="json")
    for field_name in VOLATILE_PERFORMANCE_FIELDS:
        for result in dump["tool_results"]:
            result.pop(field_name, None)
        for event in dump["trajectory"]:
            details = event.get("details")
            if isinstance(details, dict):
                details.pop(field_name, None)
    return dump


def build_runtime(loader: BenchmarkLoader, case_id: str) -> InvestigationRuntime:
    clock = TickingClock()
    return InvestigationRuntime(
        DeterministicPlanner(
            case_id=case_id, id_generator=SequentialIdGenerator(), clock=clock
        ),
        executor=ToolExecutor(loader=loader, clock=clock),
        id_generator=SequentialIdGenerator(),
        clock=clock,
    )


def payloads_by_tool(run: Any) -> dict[str, list[Any]]:
    calls = {call.tool_call_id: call.tool_name for call in run.tool_calls}
    payloads: dict[str, list[Any]] = {}
    for result in run.tool_results:
        payloads.setdefault(calls[result.tool_call_id], []).append(result.data)
    return payloads


def test_full_investigation_on_case_001_completes(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))

    assert run.status is RuntimeStatus.COMPLETED
    assert run.stop_reason is StopReason.COMPLETED
    assert run.plan is not None
    assert [step.status for step in run.plan.steps] == [
        InvestigationStepStatus.COMPLETED
    ] * len(run.plan.steps)
    assert len(run.tool_calls) == len(run.tool_results) == 9
    assert all(result.success for result in run.tool_results)


def test_endpoint_tool_path_reads_real_telemetry(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))
    payloads = payloads_by_tool(run)["search_endpoint_events"]

    event_ids = {
        event["event_id"] for payload in payloads for event in payload["items"]
    }
    assert "EPE-001-003" in event_ids
    assert any(payload["count"] == 4 for payload in payloads)


def test_network_tool_path_reads_real_telemetry(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))
    payloads = payloads_by_tool(run)["search_network_activity"]

    network_ids = {
        event["event_id"] for payload in payloads for event in payload["network_events"]
    }
    dns_ids = {event["event_id"] for payload in payloads for event in payload["dns_events"]}

    assert {"NET-001-003", "NET-001-004"} <= network_ids
    assert "DNS-001-001" in dns_ids


def test_indicator_and_cti_paths_read_real_knowledge(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))
    payloads = payloads_by_tool(run)

    ioc_payloads = payloads["lookup_ioc_reputation"]
    assert any(payload["found"] is True for payload in ioc_payloads)
    assert any(payload["found"] is False for payload in ioc_payloads)
    known = next(payload for payload in ioc_payloads if payload["found"])
    assert known["records"][0]["reputation"] == "malicious"

    cti_payloads = payloads["search_cti"]
    assert any(
        "CTI-001" in {record["cti_id"] for record in payload["cti_records"]}
        for payload in cti_payloads
    )
    assert any(payload["technique_count"] > 0 for payload in cti_payloads)


def test_zero_result_tool_calls_are_successful(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))

    zero_result_payloads = [
        result.data
        for result in run.tool_results
        if isinstance(result.data, dict) and result.data.get("count") == 0
    ]

    assert zero_result_payloads
    assert all(result.success for result in run.tool_results)


def test_file_reputation_path_finds_a_real_artifact(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_WITH_FILE_ARTIFACT).run(
        loader.load_initial_alert(CASE_WITH_FILE_ARTIFACT)
    )
    payloads = payloads_by_tool(run)["lookup_file_reputation"]

    matching = next(payload for payload in payloads if payload["count"] == 1)
    assert matching["files"][0]["file_id"] == "FILE-002-001"
    assert matching["files"][0]["file_name"] == "lsass.dmp"
    assert matching["reputations"][0]["reputation"] == "suspicious"
    assert run.status is RuntimeStatus.COMPLETED


def test_planned_steps_use_the_expected_tools(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))
    steps = run.plan.steps
    calls_by_step: dict[str, set[str]] = {}
    for call in run.tool_calls:
        calls_by_step.setdefault(call.step_id, set()).add(call.tool_name)

    assert calls_by_step[steps[0].step_id] == {"search_endpoint_events"}
    assert calls_by_step[steps[1].step_id] == {"lookup_file_reputation"}
    assert calls_by_step[steps[2].step_id] == {"search_network_activity"}
    assert calls_by_step[steps[3].step_id] == {"lookup_ioc_reputation"}
    assert calls_by_step[steps[4].step_id] == {"search_cti"}


def test_investigation_is_reproducible(loader: BenchmarkLoader) -> None:
    alert = loader.load_initial_alert(CASE_ID)

    first = build_runtime(loader, CASE_ID).run(alert)
    second = build_runtime(loader, CASE_ID).run(alert)

    # Full comparison, minus the wall-clock measurement only.
    assert normalized_run_dump(first) == normalized_run_dump(second)

    assert first.plan is not None and second.plan is not None
    assert first.plan.model_dump() == second.plan.model_dump()
    assert [step.status for step in first.plan.steps] == [
        step.status for step in second.plan.steps
    ]
    assert [
        (call.tool_call_id, call.step_id, call.tool_name, call.arguments, call.status.value)
        for call in first.tool_calls
    ] == [
        (call.tool_call_id, call.step_id, call.tool_name, call.arguments, call.status.value)
        for call in second.tool_calls
    ]
    assert [
        (result.tool_call_id, result.tool_name, result.success, result.data)
        for result in first.tool_results
    ] == [
        (result.tool_call_id, result.tool_name, result.success, result.data)
        for result in second.tool_results
    ]
    assert [
        (
            event.sequence,
            event.event_type.value,
            event.step_id,
            event.tool_call_id,
            event.tool_result_id,
        )
        for event in first.trajectory
    ] == [
        (
            event.sequence,
            event.event_type.value,
            event.step_id,
            event.tool_call_id,
            event.tool_result_id,
        )
        for event in second.trajectory
    ]
    assert (first.status, first.stop_reason) == (second.status, second.stop_reason)


def test_reproducibility_normalisation_only_strips_latency(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))

    raw = run.model_dump(mode="json")
    normalized = normalized_run_dump(run)

    # Structure, payloads and identifiers survive the normalisation untouched.
    assert len(normalized["tool_results"]) == len(raw["tool_results"]) == len(run.tool_results)
    assert len(normalized["trajectory"]) == len(raw["trajectory"])
    assert [result["tool_result_id"] for result in normalized["tool_results"]] == [
        result["tool_result_id"] for result in raw["tool_results"]
    ]
    assert [result["data"] for result in normalized["tool_results"]] == [
        result["data"] for result in raw["tool_results"]
    ]
    assert [event["event_type"] for event in normalized["trajectory"]] == [
        event["event_type"] for event in raw["trajectory"]
    ]
    assert normalized["status"] == raw["status"]
    assert normalized["plan"] == raw["plan"]

    # Only the performance measurement is gone.
    assert "latency_ms" in json.dumps(raw)
    assert "latency_ms" not in json.dumps(normalized)


def test_handoff_data_is_complete_for_t06(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))

    provenance_pairs = {
        (call.tool_call_id, result.tool_result_id)
        for call in run.tool_calls
        for result in run.tool_results
        if result.tool_call_id == call.tool_call_id
    }

    assert len(provenance_pairs) == len(run.tool_results)
    assert all(call.incident_id == run.incident_id for call in run.tool_calls)
    assert all(call.step_id in {step.step_id for step in run.plan.steps} for call in run.tool_calls)
    assert all(isinstance(result.data, dict) for result in run.tool_results)
    dumped = run.model_dump_json()
    assert '"evidence_id":' not in dumped
    assert "evd-" not in dumped.lower()


def test_trajectory_can_rebuild_the_run(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))

    event_types = [event.event_type.value for event in run.trajectory]
    decisions = [
        event.details["action"]
        for event in run.trajectory
        if event.event_type.value == "planner_decision"
    ]

    assert event_types[0] == "investigation_started"
    assert event_types[-1] == "investigation_completed"
    assert event_types.count("tool_call_created") == len(run.tool_calls)
    assert event_types.count("tool_started") == len(run.tool_calls)
    assert event_types.count("tool_succeeded") == len(run.tool_results)
    assert decisions.count(PlannerAction.CALL_TOOL.value) == len(run.tool_calls)
    assert [event.sequence for event in run.trajectory] == list(
        range(1, len(run.trajectory) + 1)
    )


def test_ticking_clock_is_used_for_all_timestamps(loader: BenchmarkLoader) -> None:
    run = build_runtime(loader, CASE_ID).run(loader.load_initial_alert(CASE_ID))

    assert run.started_at < run.completed_at
    for call in run.tool_calls:
        assert call.requested_at <= call.started_at <= call.completed_at
    for event in run.trajectory:
        assert event.timestamp.utcoffset().total_seconds() == 0
