"""Tests for the ``IOCFinding`` and ``AttackTechniqueFinding`` contracts."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas import AttackTechniqueFinding, IOCFinding, IOCReputation, IOCType


def ioc_finding_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "finding_id": "IOCF-001",
        "incident_id": "INC-001",
        "indicator": "203.0.113.10",
        "indicator_type": "ipv4",
        "reputation": "malicious",
        "confidence": 0.8,
        "evidence_ids": ["EV-001", "EV-002"],
        "tags": ["c2"],
    }
    payload.update(overrides)
    return payload


def technique_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "confidence": 0.7,
        "evidence_ids": ["EV-001"],
    }
    payload.update(overrides)
    return payload


def test_valid_ioc_finding_is_accepted() -> None:
    finding = IOCFinding(**ioc_finding_payload())

    assert finding.finding_id == "IOCF-001"
    assert finding.indicator_type is IOCType.IPV4
    assert finding.reputation is IOCReputation.MALICIOUS
    assert finding.evidence_ids == ["EV-001", "EV-002"]


@pytest.mark.parametrize("finding_id", ["IOCF001", "IOC-001", "F-001"])
def test_invalid_finding_id_prefix_is_rejected(finding_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCFinding(**ioc_finding_payload(finding_id=finding_id))

    assert exc_info.value.errors()[0]["loc"] == ("finding_id",)


@pytest.mark.parametrize("indicator", ["", "   "])
def test_empty_indicator_is_rejected(indicator: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCFinding(**ioc_finding_payload(indicator=indicator))

    assert exc_info.value.errors()[0]["loc"] == ("indicator",)


def test_unknown_indicator_type_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCFinding(**ioc_finding_payload(indicator_type="email"))

    assert exc_info.value.errors()[0]["loc"] == ("indicator_type",)


def test_ioc_finding_without_evidence_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCFinding(**ioc_finding_payload(evidence_ids=[]))

    assert exc_info.value.errors()[0]["loc"] == ("evidence_ids",)


def test_ioc_finding_with_invalid_evidence_reference_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCFinding(**ioc_finding_payload(evidence_ids=["EV-001", "TC-001"]))

    assert exc_info.value.errors()[0]["loc"] == ("evidence_ids",)


@pytest.mark.parametrize("confidence", [1.01, 2.0, -0.01])
def test_ioc_confidence_outside_unit_interval_is_rejected(confidence: float) -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCFinding(**ioc_finding_payload(confidence=confidence))

    assert exc_info.value.errors()[0]["loc"] == ("confidence",)


def test_ioc_finding_tags_default_is_not_shared_between_instances() -> None:
    payload = ioc_finding_payload()
    payload.pop("tags")

    first = IOCFinding(**payload)
    second = IOCFinding(**payload)

    first.tags.append("c2")

    assert second.tags == []


@pytest.mark.parametrize("technique_id", ["T1059", "T1059.001", "T1548.005"])
def test_valid_mitre_technique_ids_are_accepted(technique_id: str) -> None:
    finding = AttackTechniqueFinding(**technique_payload(technique_id=technique_id))

    assert finding.technique_id == technique_id


@pytest.mark.parametrize(
    "technique_id",
    [
        "1059",
        "T105",
        "T10599",
        "T1059.1",
        "T1059.0001",
        "TA0001",
        "t1059",
        "",
        "T1059.001 extra",
    ],
)
def test_invalid_mitre_technique_ids_are_rejected(technique_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        AttackTechniqueFinding(**technique_payload(technique_id=technique_id))

    assert exc_info.value.errors()[0]["loc"] == ("technique_id",)


def test_empty_technique_name_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        AttackTechniqueFinding(**technique_payload(technique_name=" "))

    assert exc_info.value.errors()[0]["loc"] == ("technique_name",)


def test_technique_without_evidence_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        AttackTechniqueFinding(**technique_payload(evidence_ids=[]))

    assert exc_info.value.errors()[0]["loc"] == ("evidence_ids",)


def test_technique_with_invalid_evidence_reference_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        AttackTechniqueFinding(**technique_payload(evidence_ids=["ALT-001"]))

    assert exc_info.value.errors()[0]["loc"] == ("evidence_ids",)
