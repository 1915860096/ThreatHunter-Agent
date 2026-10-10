"""Tests for ``ToolExecutor`` (ToolCall -> ToolResult)."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from app.benchmark.loader import BenchmarkLoader
from app.schemas.tools import ToolCall
from app.tools import SUPPORTED_TOOL_NAMES, ToolExecutor


@pytest.mark.parametrize(
    ("tool_name", "arguments", "expected"),
    [
        (
            "search_endpoint_events",
            {"case_id": "CASE-001", "process_name": "powershell.exe"},
            {"count": 4},
        ),
        (
            "search_network_activity",
            {"case_id": "CASE-001", "dst_port": 443},
            {"network_count": 4},
        ),
        (
            "lookup_file_reputation",
            {"case_id": "CASE-001", "file_name": "update.ps1"},
            {"count": 1},
        ),
        (
            "lookup_ioc_reputation",
            {"indicator": "sync-update.example.net"},
            {"found": True},
        ),
        ("search_cti", {"query": "certutil"}, {"cti_count": 1}),
    ],
)
def test_all_dispatch_paths_return_successful_results(
    executor: ToolExecutor,
    tool_call: Callable[..., ToolCall],
    tool_name: str,
    arguments: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    call = tool_call(tool_name, arguments)

    result = executor.execute(call)

    assert result.success is True
    assert result.error is None
    assert isinstance(result.data, dict)
    for key, value in expected.items():
        assert result.data[key] == value


def test_executor_links_result_to_the_tool_call(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    call = tool_call("search_endpoint_events", {"case_id": "CASE-001"}, tool_call_id="TC-042")

    result = executor.execute(call)

    assert result.tool_call_id == "TC-042"
    assert result.tool_name == "search_endpoint_events"
    assert result.tool_result_id.startswith("TR-")


def test_payload_is_serialised_as_json_ready_dict(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    result = executor.execute(
        tool_call("search_endpoint_events", {"case_id": "CASE-001", "limit": 1})
    )

    assert isinstance(result.data, dict)
    assert result.data["case_id"] == "CASE-001"
    assert result.data["count"] == 1
    assert result.data["truncated"] is True
    assert result.data["items"][0]["event_id"] == "EPE-001-001"
    assert isinstance(result.data["items"][0]["timestamp"], str)
    assert json.loads(json.dumps(result.data)) == result.data


def test_zero_results_is_still_a_success(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    result = executor.execute(
        tool_call("search_endpoint_events", {"case_id": "CASE-001", "host": "ws-missing"})
    )

    assert result.success is True
    assert result.error is None
    assert result.data["count"] == 0
    assert result.data["items"] == []


def test_tool_result_ids_increment_per_executor(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    call = tool_call("search_cti", {"query": "certutil"})

    first = executor.execute(call)
    second = executor.execute(call)

    assert (first.tool_result_id, second.tool_result_id) == ("TR-0001", "TR-0002")
    assert ToolExecutor(loader=BenchmarkLoader()).execute(call).tool_result_id == "TR-0001"


def test_returned_at_is_timezone_aware_utc(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    result = executor.execute(tool_call("search_cti", {"query": "certutil"}))

    assert result.returned_at.tzinfo is timezone.utc
    assert result.latency_ms >= 0
    assert isinstance(result.latency_ms, int)


def test_injected_clock_controls_returned_at(tool_call: Callable[..., ToolCall]) -> None:
    fixed = datetime(2026, 3, 2, 9, 30, tzinfo=timezone.utc)
    executor = ToolExecutor(clock=lambda: fixed)

    result = executor.execute(tool_call("search_cti", {"query": "certutil"}))

    assert result.returned_at == fixed


def test_unknown_tool_is_reported_as_failure(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    call = tool_call("delete_everything", {"case_id": "CASE-001"})

    result = executor.execute(call)

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert "unknown tool" in result.error
    assert result.tool_name == "delete_everything"


def test_invalid_arguments_are_reported_as_failure(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    call = tool_call("search_endpoint_events", {"case_id": "CASE-001", "limit": 0})

    result = executor.execute(call)

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert "invalid arguments" in result.error
    assert "limit" in result.error


def test_invalid_arguments_error_does_not_echo_the_input(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    sentinel = "SENTINEL-VALUE-SHOULD-NOT-BE-ECHOED"
    call = tool_call("search_endpoint_events", {"case_id": sentinel})

    result = executor.execute(call)

    assert result.success is False
    assert result.error is not None
    assert sentinel not in result.error
    assert "case_id" in result.error


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("search_endpoint_events", {"case_id": "CASE-999"}),
        ("search_network_activity", {"case_id": "CASE-999"}),
        ("lookup_file_reputation", {"case_id": "CASE-999", "file_name": "update.ps1"}),
    ],
)
def test_loader_errors_are_reported_as_failures(
    executor: ToolExecutor,
    tool_call: Callable[..., ToolCall],
    tool_name: str,
    arguments: dict[str, Any],
) -> None:
    result = executor.execute(tool_call(tool_name, arguments))

    assert result.success is False
    assert result.data is None
    assert result.error is not None
    assert "CASE-999" in result.error


def test_missing_dataset_directory_is_reported_as_failure(
    tmp_path: Path, tool_call: Callable[..., ToolCall]
) -> None:
    executor = ToolExecutor(loader=BenchmarkLoader(tmp_path / "no-dataset"))

    result = executor.execute(tool_call("search_cti", {"query": "certutil"}))

    assert result.success is False
    assert result.data is None
    assert result.error is not None


def test_executor_does_not_mutate_the_tool_call(
    executor: ToolExecutor, tool_call: Callable[..., ToolCall]
) -> None:
    call = tool_call(
        "search_network_activity", {"case_id": "CASE-001", "dst_port": 443}
    )
    before = call.model_dump(mode="json")
    arguments_before = dict(call.arguments)

    executor.execute(call)

    assert call.model_dump(mode="json") == before
    assert call.arguments == arguments_before
    assert call.status.value == "requested"


def test_executor_works_on_a_temporary_dataset_copy(
    dataset_dir: Path, tool_call: Callable[..., ToolCall]
) -> None:
    executor = ToolExecutor(loader=BenchmarkLoader(dataset_dir))

    result = executor.execute(tool_call("search_endpoint_events", {"case_id": "CASE-001"}))

    assert result.success is True
    assert result.data["count"] > 0


def test_supported_tool_names_are_declared_once() -> None:
    assert SUPPORTED_TOOL_NAMES == (
        "search_endpoint_events",
        "search_network_activity",
        "lookup_file_reputation",
        "lookup_ioc_reputation",
        "search_cti",
    )
    assert len(set(SUPPORTED_TOOL_NAMES)) == len(SUPPORTED_TOOL_NAMES)
