"""Tests for ``search_endpoint_events`` against the shipped T03 dataset."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.benchmark.loader import BenchmarkLoader
from app.tools import EndpointSearchInput, search_endpoint_events

CASE_ID = "CASE-001"

# Verified against datasets/cases/CASE-001.
ENCODED_POWERSHELL_EVENT = "EPE-001-003"
SCRIPT_FILE_EVENT = "EPE-001-004"
SCRIPT_MODIFICATION_EVENT = "EPE-001-007"
ENCODED_COMMAND_LINE = "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA"
BOUNDARY_TIMESTAMP = "2026-03-02T09:11:52Z"


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


def event_ids(payload: object) -> list[str]:
    return [event.event_id for event in payload.items]  # type: ignore[attr-defined]


def test_case_without_filters_returns_all_events_sorted(loader: BenchmarkLoader) -> None:
    payload = search_endpoint_events(EndpointSearchInput(case_id=CASE_ID), loader)
    expected = sorted(
        loader.load_endpoint_events(CASE_ID), key=lambda event: (event.timestamp, event.event_id)
    )

    assert event_ids(payload) == [event.event_id for event in expected]
    assert payload.count == len(expected)
    assert payload.truncated is False


def test_event_types_filter_combines_with_or(loader: BenchmarkLoader) -> None:
    payload = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, event_types=["file_creation", "file_modification"]),
        loader,
    )

    assert event_ids(payload) == [SCRIPT_FILE_EVENT, SCRIPT_MODIFICATION_EVENT]


def test_event_types_filter_is_case_insensitive(loader: BenchmarkLoader) -> None:
    payload = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, event_types=["PROCESS_CREATION"]), loader
    )
    expected = [
        event.event_id
        for event in sorted(
            loader.load_endpoint_events(CASE_ID),
            key=lambda event: (event.timestamp, event.event_id),
        )
        if event.event_type == "process_creation"
    ]

    assert event_ids(payload) == expected


@pytest.mark.parametrize(
    "filters",
    [
        {"host": "WS-FIN-014"},
        {"user": "D.MOREAU"},
        {"process_name": "POWERSHELL.EXE"},
        {"parent_process_name": "WINWORD.EXE"},
        {"file_path": "c:\\users\\d.moreau\\appdata\\local\\temp\\update.ps1"},
    ],
)
def test_scalar_filters_match_case_insensitively(
    loader: BenchmarkLoader, filters: dict[str, str]
) -> None:
    payload = search_endpoint_events(EndpointSearchInput(case_id=CASE_ID, **filters), loader)
    expected_ids = [
        event.event_id
        for event in sorted(
            loader.load_endpoint_events(CASE_ID),
            key=lambda event: (event.timestamp, event.event_id),
        )
        if all(
            (getattr(event, field) or "").casefold() == value.casefold()
            for field, value in filters.items()
        )
    ]

    assert event_ids(payload) == expected_ids
    assert payload.count > 0


def test_command_line_contains_is_a_case_insensitive_substring(loader: BenchmarkLoader) -> None:
    payload = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, command_line_contains="ENCODEDcommand"), loader
    )

    assert event_ids(payload) == [ENCODED_POWERSHELL_EVENT]
    assert ENCODED_COMMAND_LINE in (payload.items[0].command_line or "")


def test_process_name_is_exact_and_not_a_substring(loader: BenchmarkLoader) -> None:
    payload = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, process_name="powershell"), loader
    )

    assert payload.count == 0
    assert payload.items == []
    assert payload.truncated is False


def test_distinct_filters_combine_with_and(loader: BenchmarkLoader) -> None:
    matching = search_endpoint_events(
        EndpointSearchInput(
            case_id=CASE_ID,
            event_types=["process_creation"],
            host="ws-fin-014",
            process_name="powershell.exe",
        ),
        loader,
    )
    contradicting = search_endpoint_events(
        EndpointSearchInput(
            case_id=CASE_ID,
            process_name="powershell.exe",
            user="SYSTEM",
        ),
        loader,
    )

    assert event_ids(matching) == [ENCODED_POWERSHELL_EVENT]
    assert contradicting.count == 0


def test_time_window_boundaries_are_inclusive(loader: BenchmarkLoader) -> None:
    start_only = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, start_time=BOUNDARY_TIMESTAMP), loader
    )
    end_only = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, end_time=BOUNDARY_TIMESTAMP), loader
    )

    assert ENCODED_POWERSHELL_EVENT in event_ids(start_only)
    assert ENCODED_POWERSHELL_EVENT in event_ids(end_only)
    assert start_only.count + end_only.count > len(loader.load_endpoint_events(CASE_ID))


def test_time_window_excludes_events_outside_the_range(loader: BenchmarkLoader) -> None:
    payload = search_endpoint_events(
        EndpointSearchInput(
            case_id=CASE_ID,
            start_time="2026-03-02T09:11:52Z",
            end_time="2026-03-02T09:12:12Z",
        ),
        loader,
    )

    assert event_ids(payload) == [
        "EPE-001-002",
        ENCODED_POWERSHELL_EVENT,
        SCRIPT_FILE_EVENT,
        "EPE-001-005",
        "EPE-001-006",
        SCRIPT_MODIFICATION_EVENT,
    ]


def test_zero_results_is_a_successful_empty_payload(loader: BenchmarkLoader) -> None:
    payload = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, process_name="not-a-real-process.exe"), loader
    )

    assert payload.items == []
    assert payload.count == 0
    assert payload.truncated is False


def test_results_are_deterministic_across_calls(loader: BenchmarkLoader) -> None:
    request = EndpointSearchInput(case_id=CASE_ID, host="ws-fin-014")

    first = search_endpoint_events(request, loader)
    second = search_endpoint_events(request, loader)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_truncation_reports_hidden_matches(loader: BenchmarkLoader) -> None:
    limited = search_endpoint_events(EndpointSearchInput(case_id=CASE_ID, limit=1), loader)
    complete = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, limit=500), loader
    )

    assert limited.count == 1
    assert limited.truncated is True
    assert complete.count == len(loader.load_endpoint_events(CASE_ID))
    assert complete.truncated is False


def test_sha256_filter_matches_only_recorded_hashes(loader: BenchmarkLoader) -> None:
    # Endpoint telemetry never records a file hash in the shipped dataset, so a
    # hash filter legitimately finds nothing.
    payload = search_endpoint_events(
        EndpointSearchInput(
            case_id=CASE_ID,
            sha256="41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc00",
        ),
        loader,
    )

    assert payload.count == 0


def test_sha256_filter_can_match_when_telemetry_records_a_hash(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / CASE_ID / "telemetry" / "endpoint_events.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    digest = "41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc00"
    payload[2]["sha256"] = digest
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = search_endpoint_events(
        EndpointSearchInput(case_id=CASE_ID, sha256=digest),
        BenchmarkLoader(dataset_dir),
    )

    assert event_ids(result) == [ENCODED_POWERSHELL_EVENT]
