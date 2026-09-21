"""Tests for the ``ToolCall`` and ``ToolResult`` contracts."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas import ToolCall, ToolCallStatus, ToolResult


def tool_call_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool_call_id": "TC-001",
        "incident_id": "INC-001",
        "step_id": "STEP-001",
        "tool_name": "process_tree",
        "arguments": {"host": "ws-042", "pid": 4711},
        "rationale": "Identify child processes of the alerting process",
        "status": "requested",
        "requested_at": "2026-09-22T10:00:00Z",
    }
    payload.update(overrides)
    return payload


def tool_result_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool_result_id": "TR-001",
        "tool_call_id": "TC-001",
        "tool_name": "process_tree",
        "success": True,
        "data": {"children": ["cmd.exe", "rundll32.exe"]},
        "latency_ms": 128,
        "returned_at": "2026-09-22T10:00:01Z",
    }
    payload.update(overrides)
    return payload


def test_valid_tool_call_is_accepted() -> None:
    call = ToolCall(**tool_call_payload())

    assert call.tool_call_id == "TC-001"
    assert call.status is ToolCallStatus.REQUESTED
    assert call.arguments == {"host": "ws-042", "pid": 4711}
    assert call.started_at is None
    assert call.completed_at is None


def test_tool_call_arguments_default_is_not_shared_between_instances() -> None:
    payload = tool_call_payload()
    payload.pop("arguments")

    first = ToolCall(**payload)
    second = ToolCall(**payload)

    first.arguments["host"] = "ws-042"

    assert second.arguments == {}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool_call_id", "TC001"),
        ("incident_id", "INC001"),
        ("step_id", "STEP001"),
    ],
)
def test_invalid_tool_call_id_prefixes_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        ToolCall(**tool_call_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_empty_tool_name_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ToolCall(**tool_call_payload(tool_name="  "))

    assert exc_info.value.errors()[0]["loc"] == ("tool_name",)


def test_naive_requested_at_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ToolCall(**tool_call_payload(requested_at="2026-09-22T10:00:00"))

    assert exc_info.value.errors()[0]["loc"] == ("requested_at",)


def test_unknown_tool_call_status_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ToolCall(**tool_call_payload(status="timeout"))

    assert exc_info.value.errors()[0]["loc"] == ("status",)


def test_tool_call_completed_at_before_started_at_is_rejected() -> None:
    with pytest.raises(ValidationError, match="completed_at must not be earlier"):
        ToolCall(
            **tool_call_payload(
                status="succeeded",
                started_at="2026-09-22T10:00:05Z",
                completed_at="2026-09-22T10:00:01Z",
            )
        )


def test_tool_call_with_consistent_timestamps_is_accepted() -> None:
    call = ToolCall(
        **tool_call_payload(
            status="succeeded",
            started_at="2026-09-22T10:00:01Z",
            completed_at="2026-09-22T10:00:02Z",
        )
    )

    assert call.status is ToolCallStatus.SUCCEEDED


def test_valid_successful_tool_result_is_accepted() -> None:
    result = ToolResult(**tool_result_payload())

    assert result.success is True
    assert result.error is None
    assert result.latency_ms == 128
    assert result.data == {"children": ["cmd.exe", "rundll32.exe"]}


@pytest.mark.parametrize("data", [None, {"key": "value"}, [1, 2, 3]])
def test_tool_result_data_accepts_dict_list_or_none(data: Any) -> None:
    result = ToolResult(**tool_result_payload(data=data))

    assert result.data == data


def test_successful_tool_result_with_error_is_rejected() -> None:
    with pytest.raises(ValidationError, match="error must be None"):
        ToolResult(**tool_result_payload(success=True, error="partial failure"))


@pytest.mark.parametrize("error", [None, "", "   "])
def test_failed_tool_result_without_error_is_rejected(error: str | None) -> None:
    with pytest.raises(ValidationError, match="error is required"):
        ToolResult(**tool_result_payload(success=False, error=error, data=None))


def test_failed_tool_result_with_error_is_accepted() -> None:
    result = ToolResult(
        **tool_result_payload(success=False, error="connection refused", data=None)
    )

    assert result.success is False
    assert result.error == "connection refused"


@pytest.mark.parametrize("latency_ms", [-1, -1000])
def test_negative_latency_is_rejected(latency_ms: int) -> None:
    with pytest.raises(ValidationError) as exc_info:
        ToolResult(**tool_result_payload(latency_ms=latency_ms))

    assert exc_info.value.errors()[0]["loc"] == ("latency_ms",)


def test_zero_latency_is_accepted() -> None:
    assert ToolResult(**tool_result_payload(latency_ms=0)).latency_ms == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool_result_id", "TR001"),
        ("tool_call_id", "TC001"),
    ],
)
def test_invalid_tool_result_id_prefixes_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        ToolResult(**tool_result_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_naive_returned_at_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ToolResult(**tool_result_payload(returned_at="2026-09-22T10:00:01"))

    assert exc_info.value.errors()[0]["loc"] == ("returned_at",)
