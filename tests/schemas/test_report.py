"""Tests for the ``InvestigationReport`` and its support value objects."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas import (
    InvestigationReport,
    InvestigationVerdict,
    Recommendation,
    RecommendationPriority,
    TimelineEvent,
)


def report_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "report_id": "RPT-001",
        "incident_id": "INC-001",
        "alert_id": "ALT-001",
        "verdict": "malicious",
        "confidence": 0.85,
        "summary": "Encoded PowerShell execution with C2 beaconing.",
        "iocs": [
            {
                "finding_id": "IOCF-001",
                "incident_id": "INC-001",
                "indicator": "203.0.113.10",
                "indicator_type": "ipv4",
                "reputation": "malicious",
                "confidence": 0.8,
                "evidence_ids": ["EV-001"],
            }
        ],
        "attack_techniques": [
            {
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "confidence": 0.7,
                "evidence_ids": ["EV-001"],
            }
        ],
        "evidence_ids": ["EV-001", "EV-002"],
        "timeline": [
            {
                "timestamp": "2026-09-22T09:59:58Z",
                "description": "powershell.exe spawned cmd.exe",
                "evidence_ids": ["EV-001"],
            }
        ],
        "recommendations": [
            {
                "action": "Isolate ws-042",
                "priority": "high",
                "rationale": "Active C2 channel from the host",
                "evidence_ids": ["EV-002"],
            }
        ],
        "generated_at": "2026-09-22T10:10:00Z",
    }
    payload.update(overrides)
    return payload


def test_valid_report_is_accepted() -> None:
    report = InvestigationReport(**report_payload())

    assert report.report_id == "RPT-001"
    assert report.verdict is InvestigationVerdict.MALICIOUS
    assert report.confidence == 0.85
    assert len(report.iocs) == 1
    assert len(report.attack_techniques) == 1
    assert len(report.timeline) == 1
    assert len(report.recommendations) == 1
    assert report.evidence_ids == ["EV-001", "EV-002"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("report_id", "RPT001"),
        ("incident_id", "INC001"),
        ("alert_id", "ALT001"),
    ],
)
def test_invalid_report_id_prefixes_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationReport(**report_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


@pytest.mark.parametrize("verdict", ["malicious", "suspicious"])
def test_report_with_assertive_verdict_requires_evidence(verdict: str) -> None:
    with pytest.raises(ValidationError, match="at least one evidence item"):
        InvestigationReport(**report_payload(verdict=verdict, evidence_ids=[]))


@pytest.mark.parametrize("verdict", ["malicious", "suspicious"])
def test_report_with_assertive_verdict_and_evidence_is_accepted(verdict: str) -> None:
    report = InvestigationReport(**report_payload(verdict=verdict))

    assert report.verdict.value == verdict
    assert report.evidence_ids


def test_inconclusive_report_without_evidence_is_accepted() -> None:
    report = InvestigationReport(**report_payload(verdict="inconclusive", evidence_ids=[]))

    assert report.verdict is InvestigationVerdict.INCONCLUSIVE
    assert report.evidence_ids == []


def test_benign_report_without_evidence_is_accepted() -> None:
    report = InvestigationReport(**report_payload(verdict="benign", evidence_ids=[]))

    assert report.verdict is InvestigationVerdict.BENIGN


def test_report_rejects_malformed_evidence_id() -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationReport(**report_payload(evidence_ids=["EV-001", "EV002"]))

    assert exc_info.value.errors()[0]["loc"] == ("evidence_ids",)


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_report_confidence_outside_unit_interval_is_rejected(confidence: float) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationReport(**report_payload(confidence=confidence))

    assert exc_info.value.errors()[0]["loc"] == ("confidence",)


@pytest.mark.parametrize("confidence", [0.0, 1.0])
def test_report_confidence_bounds_are_inclusive(confidence: float) -> None:
    assert InvestigationReport(**report_payload(confidence=confidence)).confidence == confidence


@pytest.mark.parametrize("summary", ["", "   "])
def test_empty_report_summary_is_rejected(summary: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationReport(**report_payload(summary=summary))

    assert exc_info.value.errors()[0]["loc"] == ("summary",)


@pytest.mark.parametrize("generated_at", ["2026-09-22T10:10:00", "2026-09-22"])
def test_naive_generated_at_is_rejected(generated_at: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationReport(**report_payload(generated_at=generated_at))

    assert exc_info.value.errors()[0]["loc"] == ("generated_at",)


def test_unknown_verdict_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationReport(**report_payload(verdict="probably_bad"))

    assert exc_info.value.errors()[0]["loc"] == ("verdict",)


def test_report_lists_default_to_empty_and_are_not_shared() -> None:
    payload = report_payload(verdict="inconclusive")
    for field in ("iocs", "attack_techniques", "evidence_ids", "timeline", "recommendations"):
        payload.pop(field)

    first = InvestigationReport(**payload)
    second = InvestigationReport(**payload)

    first.timeline.append(
        TimelineEvent(timestamp="2026-09-22T10:00:00Z", description="first event")
    )
    first.recommendations.append(
        Recommendation(
            action="Collect disk image",
            priority="medium",
            rationale="Preserve volatile state",
        )
    )

    assert second.timeline == []
    assert second.recommendations == []
    assert second.iocs == []
    assert second.attack_techniques == []
    assert second.evidence_ids == []


def test_timeline_event_requires_aware_timestamp_and_description() -> None:
    with pytest.raises(ValidationError) as exc_info:
        TimelineEvent(timestamp="2026-09-22T10:00:00", description="event")

    assert exc_info.value.errors()[0]["loc"] == ("timestamp",)

    with pytest.raises(ValidationError) as exc_info:
        TimelineEvent(timestamp="2026-09-22T10:00:00Z", description=" ")

    assert exc_info.value.errors()[0]["loc"] == ("description",)


def test_timeline_event_rejects_malformed_evidence_reference() -> None:
    with pytest.raises(ValidationError) as exc_info:
        TimelineEvent(
            timestamp="2026-09-22T10:00:00Z",
            description="event",
            evidence_ids=["EV-001", "ALT-002"],
        )

    assert exc_info.value.errors()[0]["loc"] == ("evidence_ids",)


def test_recommendation_requires_action_and_rationale() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Recommendation(action="", priority="high", rationale="Because")

    assert exc_info.value.errors()[0]["loc"] == ("action",)

    with pytest.raises(ValidationError) as exc_info:
        Recommendation(action="Isolate host", priority="high", rationale=" ")

    assert exc_info.value.errors()[0]["loc"] == ("rationale",)


def test_recommendation_rejects_unknown_priority() -> None:
    with pytest.raises(ValidationError) as exc_info:
        Recommendation(action="Isolate host", priority="urgent", rationale="Active C2")

    assert exc_info.value.errors()[0]["loc"] == ("priority",)


def test_recommendation_priority_enum_values() -> None:
    recommendation = Recommendation(
        action="Isolate host",
        priority=RecommendationPriority.CRITICAL,
        rationale="Active C2",
    )

    assert recommendation.priority is RecommendationPriority.CRITICAL
    assert recommendation.evidence_ids == []
