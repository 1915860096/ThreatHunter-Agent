"""Tests for the T06 evidence contracts."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.evidence import EvidenceExtractionResult, EvidenceSourceReference
from app.schemas.evidence import (
    Evidence,
    EvidenceProvenance,
    EvidenceSourceType,
    EvidenceType,
)
from tests.conftest import CASE_ID, INCIDENT_ID, START


def source_reference(**overrides: object) -> EvidenceSourceReference:
    payload: dict[str, object] = {
        "source_type": EvidenceSourceType.TOOL,
        "source_name": "search_endpoint_events",
        "tool_call_id": "TC-000001",
        "tool_result_id": "TR-0001",
        "record_id": "EPE-001-003",
        "raw_ref": "CASE-001/telemetry/endpoint_events.json#EPE-001-003",
        "source_fields": ["event_type", "host"],
    }
    payload.update(overrides)
    return EvidenceSourceReference(**payload)  # type: ignore[arg-type]


def evidence(evidence_id: str = "EV-000001") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        incident_id=INCIDENT_ID,
        evidence_type=EvidenceType.PROCESS_EXECUTION,
        summary="Host ws-fin-014: process_creation",
        content={"record_id": "EPE-001-003"},
        observed_at=START,
        collected_at=START,
        reliability=0.9,
        provenance=EvidenceProvenance(
            source_type=EvidenceSourceType.TOOL,
            source_name="search_endpoint_events",
            tool_call_id="TC-000001",
            tool_result_id="TR-0001",
            raw_ref="CASE-001/telemetry/endpoint_events.json#EPE-001-003",
        ),
        tags=["source-class:telemetry"],
    )


def test_source_reference_requires_provenance_fields() -> None:
    reference = source_reference()

    assert reference.tool_call_id == "TC-000001"
    assert reference.tool_result_id == "TR-0001"
    assert reference.source_fields == ["event_type", "host"]


@pytest.mark.parametrize("field", ["tool_call_id", "tool_result_id"])
def test_source_reference_enforces_id_prefixes(field: str) -> None:
    with pytest.raises(ValidationError):
        source_reference(**{field: "XXX-000001"})


@pytest.mark.parametrize("field", ["source_name", "record_id", "raw_ref"])
def test_source_reference_rejects_empty_text(field: str) -> None:
    with pytest.raises(ValidationError):
        source_reference(**{field: "  "})


def test_extraction_result_defaults_are_independent() -> None:
    first = EvidenceExtractionResult(incident_id=INCIDENT_ID, case_id=CASE_ID)
    second = EvidenceExtractionResult(incident_id=INCIDENT_ID, case_id=CASE_ID)

    first.extraction_warnings.append("warning")

    assert first.evidence == []
    assert first.sources == {}
    assert first.candidate_count == 0
    assert second.extraction_warnings == []


def test_extraction_result_accepts_evidence_with_sources() -> None:
    result = EvidenceExtractionResult(
        incident_id=INCIDENT_ID,
        case_id=CASE_ID,
        evidence=[evidence()],
        sources={"EV-000001": [source_reference()]},
        processed_tool_result_ids=["TR-0001"],
        candidate_count=2,
        extraction_warnings=["TR-0002: unsupported payload"],
    )

    assert result.evidence_count == 1
    assert result.duplicate_hit_count == 1
    assert result.source_reference_count == 1
    assert result.evidence_type_counts == {"process_execution": 1}
    assert result.evidence_ids() == ["EV-000001"]
    assert result.evidence_of_type(EvidenceType.PROCESS_EXECUTION) == result.evidence
    assert result.sources_of("EV-000001")[0].record_id == "EPE-001-003"


def test_extraction_result_requires_sources_for_every_evidence() -> None:
    with pytest.raises(ValidationError, match="missing=\\['EV-000001'\\]"):
        EvidenceExtractionResult(
            incident_id=INCIDENT_ID, case_id=CASE_ID, evidence=[evidence()], sources={}
        )


def test_extraction_result_rejects_unknown_source_keys() -> None:
    with pytest.raises(ValidationError, match="unknown=\\['EV-000009'\\]"):
        EvidenceExtractionResult(
            incident_id=INCIDENT_ID,
            case_id=CASE_ID,
            sources={"EV-000009": [source_reference()]},
        )


def test_extraction_result_rejects_empty_reference_lists() -> None:
    with pytest.raises(ValidationError, match="at least one source reference"):
        EvidenceExtractionResult(
            incident_id=INCIDENT_ID,
            case_id=CASE_ID,
            evidence=[evidence()],
            sources={"EV-000001": []},
        )


def test_extraction_result_rejects_duplicate_evidence_ids() -> None:
    with pytest.raises(ValidationError, match="unique"):
        EvidenceExtractionResult(
            incident_id=INCIDENT_ID,
            case_id=CASE_ID,
            evidence=[evidence(), evidence()],
            sources={"EV-000001": [source_reference()]},
        )


def test_extraction_result_json_round_trip() -> None:
    result = EvidenceExtractionResult(
        incident_id=INCIDENT_ID,
        case_id=CASE_ID,
        evidence=[evidence()],
        sources={"EV-000001": [source_reference()]},
        processed_tool_result_ids=["TR-0001"],
        candidate_count=1,
    )

    dumped = json.loads(result.model_dump_json())
    reloaded = EvidenceExtractionResult.model_validate(dumped)

    assert reloaded == result
    assert dumped["evidence"][0]["provenance"]["raw_ref"].endswith("#EPE-001-003")


def test_evidence_type_counts_are_sorted() -> None:
    result = EvidenceExtractionResult(
        incident_id=INCIDENT_ID,
        case_id=CASE_ID,
        evidence=[evidence("EV-000002"), evidence("EV-000001")],
        sources={
            "EV-000001": [source_reference()],
            "EV-000002": [source_reference(tool_call_id="TC-000002", tool_result_id="TR-0002")],
        },
    )

    assert list(result.evidence_type_counts) == ["process_execution"]
    assert list(result.evidence_ids()) == ["EV-000002", "EV-000001"]
