"""Tests for the ``Evidence`` and ``EvidenceProvenance`` contracts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas import Evidence, EvidenceProvenance, EvidenceSourceType, EvidenceType


def evidence_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "evidence_id": "EV-001",
        "incident_id": "INC-001",
        "evidence_type": "process_execution",
        "summary": "powershell.exe spawned cmd.exe",
        "content": {"parent_process": "powershell.exe", "process": "cmd.exe"},
        "observed_at": "2026-09-22T09:59:58Z",
        "collected_at": "2026-09-22T10:00:01Z",
        "reliability": 0.9,
        "provenance": {
            "source_type": "tool",
            "source_name": "process_tree",
            "tool_call_id": "TC-001",
            "tool_result_id": "TR-001",
            "raw_ref": "tool_results/TR-001.json",
        },
        "tags": ["process", "execution"],
    }
    payload.update(overrides)
    return payload


def test_valid_evidence_is_accepted() -> None:
    evidence = Evidence(**evidence_payload())

    assert evidence.evidence_id == "EV-001"
    assert evidence.evidence_type is EvidenceType.PROCESS_EXECUTION
    assert evidence.reliability == 0.9
    assert evidence.provenance.source_type is EvidenceSourceType.TOOL
    assert evidence.provenance.raw_ref == "tool_results/TR-001.json"
    assert evidence.tags == ["process", "execution"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_id", "EV001"),
        ("incident_id", "INC001"),
    ],
)
def test_invalid_evidence_id_prefixes_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**evidence_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


@pytest.mark.parametrize("summary", ["", "   "])
def test_empty_evidence_summary_is_rejected(summary: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**evidence_payload(summary=summary))

    assert exc_info.value.errors()[0]["loc"] == ("summary",)


def test_empty_evidence_content_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**evidence_payload(content={}))

    assert exc_info.value.errors()[0]["loc"] == ("content",)


@pytest.mark.parametrize("reliability", [-0.01, -1.0])
def test_reliability_below_zero_is_rejected(reliability: float) -> None:
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**evidence_payload(reliability=reliability))

    assert exc_info.value.errors()[0]["loc"] == ("reliability",)


@pytest.mark.parametrize("reliability", [1.01, 2.0])
def test_reliability_above_one_is_rejected(reliability: float) -> None:
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**evidence_payload(reliability=reliability))

    assert exc_info.value.errors()[0]["loc"] == ("reliability",)


@pytest.mark.parametrize("reliability", [0.0, 1.0])
def test_reliability_bounds_are_inclusive(reliability: float) -> None:
    assert Evidence(**evidence_payload(reliability=reliability)).reliability == reliability


def test_naive_observed_at_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**evidence_payload(observed_at=datetime(2026, 9, 22, 9, 59, 58)))

    assert exc_info.value.errors()[0]["loc"] == ("observed_at",)


def test_observed_at_is_normalised_to_utc() -> None:
    evidence = Evidence(**evidence_payload(observed_at="2026-09-22T17:59:58+08:00"))

    assert evidence.observed_at == datetime(2026, 9, 22, 9, 59, 58, tzinfo=timezone.utc)


def test_naive_collected_at_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**evidence_payload(collected_at="2026-09-22T10:00:01"))

    assert exc_info.value.errors()[0]["loc"] == ("collected_at",)


def test_collected_at_is_normalised_to_utc() -> None:
    evidence = Evidence(
        **evidence_payload(
            collected_at=datetime(2026, 9, 22, 18, 0, tzinfo=timezone(timedelta(hours=8)))
        )
    )

    assert evidence.collected_at == datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)


def test_tool_provenance_without_tool_references_is_rejected() -> None:
    with pytest.raises(ValidationError, match="tool_call_id and tool_result_id are required"):
        EvidenceProvenance(source_type="tool", source_name="process_tree")


def test_tool_provenance_with_partial_references_is_rejected() -> None:
    with pytest.raises(ValidationError, match="tool_call_id and tool_result_id are required"):
        EvidenceProvenance(
            source_type="tool", source_name="process_tree", tool_call_id="TC-001"
        )


def test_tool_provenance_with_both_references_is_accepted() -> None:
    provenance = EvidenceProvenance(
        source_type="tool",
        source_name="process_tree",
        tool_call_id="TC-001",
        tool_result_id="TR-001",
    )

    assert provenance.tool_call_id == "TC-001"
    assert provenance.tool_result_id == "TR-001"


def test_provenance_rejects_malformed_tool_reference() -> None:
    with pytest.raises(ValidationError) as exc_info:
        EvidenceProvenance(
            source_type="tool",
            source_name="process_tree",
            tool_call_id="TC001",
            tool_result_id="TR001",
        )

    locations = {error["loc"][0] for error in exc_info.value.errors()}
    assert locations == {"tool_call_id", "tool_result_id"}


@pytest.mark.parametrize("source_type", ["alert", "knowledge", "analyst"])
def test_non_tool_provenance_needs_no_tool_references(source_type: str) -> None:
    provenance = EvidenceProvenance(source_type=source_type, source_name="analyst-note")

    assert provenance.tool_call_id is None
    assert provenance.tool_result_id is None


def test_empty_provenance_source_name_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        EvidenceProvenance(source_type="analyst", source_name="")

    assert exc_info.value.errors()[0]["loc"] == ("source_name",)


def test_unknown_evidence_type_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**evidence_payload(evidence_type="registry_change"))

    assert exc_info.value.errors()[0]["loc"] == ("evidence_type",)


def test_evidence_tags_default_is_not_shared_between_instances() -> None:
    payload = evidence_payload()
    payload.pop("tags")

    first = Evidence(**payload)
    second = Evidence(**payload)

    first.tags.append("process")

    assert second.tags == []
