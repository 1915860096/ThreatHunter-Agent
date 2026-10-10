"""Tests for trajectory recording and detail sanitisation."""

from __future__ import annotations

from app.runtime import TrajectoryEventType, TrajectoryRecorder, sanitize_details
from tests.runtime.conftest import TickingClock


def test_sequence_starts_at_one_and_increases_strictly() -> None:
    recorder = TrajectoryRecorder(incident_id="INC-000001", clock=TickingClock())

    first = recorder.record(TrajectoryEventType.INVESTIGATION_STARTED)
    second = recorder.record(TrajectoryEventType.PLAN_CREATED)
    third = recorder.record(TrajectoryEventType.STEP_STARTED, step_id="STEP-000001")

    assert [first.sequence, second.sequence, third.sequence] == [1, 2, 3]
    assert recorder.next_sequence == 4


def test_recorder_uses_the_injected_clock() -> None:
    clock = TickingClock()
    recorder = TrajectoryRecorder(incident_id="INC-000001", clock=clock)

    first = recorder.record(TrajectoryEventType.INVESTIGATION_STARTED)
    second = recorder.record(TrajectoryEventType.PLAN_CREATED)

    assert second.timestamp > first.timestamp
    assert first.timestamp.utcoffset().total_seconds() == 0


def test_recorder_propagates_incident_and_reference_ids() -> None:
    recorder = TrajectoryRecorder(incident_id="INC-000007", clock=TickingClock())

    event = recorder.record(
        TrajectoryEventType.TOOL_SUCCEEDED,
        step_id="STEP-000001",
        tool_call_id="TC-000001",
        tool_result_id="TR-0001",
    )

    assert event.incident_id == "INC-000007"
    assert event.step_id == "STEP-000001"
    assert event.tool_call_id == "TC-000001"
    assert event.tool_result_id == "TR-0001"


def test_events_property_returns_a_copy() -> None:
    recorder = TrajectoryRecorder(incident_id="INC-000001", clock=TickingClock())
    recorder.record(TrajectoryEventType.INVESTIGATION_STARTED)

    events = recorder.events
    events.clear()

    assert len(recorder.events) == 1


def test_sanitize_details_drops_sensitive_keys() -> None:
    details = sanitize_details(
        {
            "tool_name": "search_cti",
            "api_key": "sk-should-not-be-stored",
            "token": "secret-token",
            "password": "hunter2",
            "traceback": "Traceback (most recent call last): ...",
            "ground_truth": {"verdict": "malicious"},
            "expected_verdict": "malicious",
            "key_evidence": ["EPE-001-003"],
            "data": {"items": [{"event_id": "EPE-001-003"}]},
            "payload": {"records": []},
        }
    )

    assert details == {"tool_name": "search_cti"}


def test_sanitize_details_keeps_scalars_and_scalar_lists() -> None:
    details = sanitize_details(
        {
            "attempt": 2,
            "success": True,
            "latency_ms": None,
            "event_types": ["process_creation", "file_creation"],
            "nested": {"case_id": "CASE-001"},
            "records": [{"event_id": "EPE-001-003"}],
        }
    )

    assert details["attempt"] == 2
    assert details["success"] is True
    assert details["latency_ms"] is None
    assert details["event_types"] == ["process_creation", "file_creation"]
    assert details["nested"] == {"type": "dict", "keys": ["case_id"]}
    assert details["records"] == {"type": "list", "length": 1}


def test_sanitize_details_truncates_long_strings() -> None:
    details = sanitize_details({"error": "x" * 500})

    assert len(details["error"]) < 500
    assert details["error"].endswith("...")


def test_sanitize_details_handles_empty_input() -> None:
    assert sanitize_details(None) == {}
    assert sanitize_details({}) == {}


def test_recorded_details_are_sanitised() -> None:
    recorder = TrajectoryRecorder(incident_id="INC-000001", clock=TickingClock())

    event = recorder.record(
        TrajectoryEventType.TOOL_FAILED,
        details={"tool_name": "search_cti", "token": "nope", "data": {"records": []}},
    )

    assert event.details == {"tool_name": "search_cti"}


def test_trajectory_details_cannot_duplicate_a_tool_payload() -> None:
    payload = {"items": [{"event_id": "EPE-001-003"}], "count": 1, "truncated": False}
    details = sanitize_details({"result": payload, "count": payload["count"]})

    # Only a compact summary of the container survives, never its contents.
    assert details["result"] == {"type": "dict", "keys": ["count", "items", "truncated"]}
    assert "EPE-001-003" not in str(details)
    assert "event_id" not in str(details)
    assert details["count"] == 1
