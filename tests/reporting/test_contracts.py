"""Tests for the T06 summary contracts."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.reporting import (
    InvestigationSummary,
    SummaryObservation,
    SummaryObservationCategory,
)
from app.runtime.contracts import RuntimeStatus, StopReason
from tests.conftest import CASE_ID, INCIDENT_ID, START


def observation(evidence_ids: list[str] | None = None) -> SummaryObservation:
    return SummaryObservation(
        category=SummaryObservationCategory.OBSERVED_ACTIVITY,
        title="Process activity on ws-fin-014: powershell.exe",
        description="2 endpoint event(s) recorded for process powershell.exe.",
        evidence_ids=evidence_ids if evidence_ids is not None else ["EV-000001"],
    )


def summary(**overrides: object) -> InvestigationSummary:
    payload: dict[str, object] = {
        "incident_id": INCIDENT_ID,
        "case_id": CASE_ID,
        "status": RuntimeStatus.COMPLETED,
        "stop_reason": StopReason.COMPLETED,
        "tool_call_count": 2,
        "evidence_count": 1,
        "observations": [observation()],
        "information_gaps": ["gap"],
        "limitations": ["limitation"],
        "evidence_type_counts": {"process_execution": 1},
        "evidence_ids": ["EV-000001"],
        "unlinked_knowledge_evidence_ids": [],
        "generated_at": START,
    }
    payload.update(overrides)
    return InvestigationSummary(**payload)  # type: ignore[arg-type]


def test_observation_requires_evidence() -> None:
    assert observation().evidence_ids == ["EV-000001"]

    with pytest.raises(ValidationError):
        observation([])


@pytest.mark.parametrize("evidence_id", ["EV-000001", "EV-000999"])
def test_observation_accepts_ev_prefixed_ids(evidence_id: str) -> None:
    assert observation([evidence_id]).evidence_ids == [evidence_id]


@pytest.mark.parametrize("evidence_id", ["EVD-000001", "TC-000001", "1"])
def test_observation_rejects_foreign_id_prefixes(evidence_id: str) -> None:
    with pytest.raises(ValidationError):
        observation([evidence_id])


def test_observation_forbids_verdict_like_extra_fields() -> None:
    with pytest.raises(ValidationError):
        SummaryObservation(
            category=SummaryObservationCategory.OBSERVED_ACTIVITY,
            title="Title",
            description="Description",
            evidence_ids=["EV-000001"],
            verdict="malicious",
        )


def test_summary_valid_example() -> None:
    built = summary()

    assert built.observation_count == 1
    assert built.gap_count == 1
    assert built.observations_of_category(
        SummaryObservationCategory.OBSERVED_ACTIVITY
    ) == built.observations
    assert built.observations_of_category(
        SummaryObservationCategory.CTI_KNOWLEDGE_REFERENCE
    ) == []


def test_summary_forbids_verdict_fields() -> None:
    with pytest.raises(ValidationError):
        summary(verdict="malicious")

    with pytest.raises(ValidationError):
        summary(confidence=0.9)


def test_summary_validates_evidence_count() -> None:
    with pytest.raises(ValidationError, match="evidence_ids must list"):
        summary(evidence_count=2)


def test_summary_validates_observation_references() -> None:
    with pytest.raises(ValidationError, match="references unknown evidence"):
        summary(observations=[observation(["EV-000002"])])


def test_summary_validates_unlinked_knowledge_ids() -> None:
    with pytest.raises(ValidationError, match="is not part of the run"):
        summary(unlinked_knowledge_evidence_ids=["EV-000003"])


def test_summary_defaults_are_independent() -> None:
    first = summary(observations=[], information_gaps=[], limitations=[], evidence_count=1)
    second = summary(observations=[], information_gaps=[], limitations=[], evidence_count=1)

    first.information_gaps.append("new gap")

    assert second.information_gaps == []


def test_summary_json_round_trip() -> None:
    built = summary()

    dumped = json.loads(built.model_dump_json())
    reloaded = InvestigationSummary.model_validate(dumped)

    assert reloaded == built
    assert dumped["observations"][0]["category"] == "observed_activity"
    assert dumped["status"] == "completed"
