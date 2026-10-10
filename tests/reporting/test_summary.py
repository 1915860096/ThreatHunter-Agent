"""Tests for the deterministic summary builder on real and scripted runs."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.evidence.extractor import (
    TOOL_LOOKUP_IOC_REPUTATION,
    TOOL_SEARCH_CTI,
    TOOL_SEARCH_ENDPOINT,
)
from app.reporting import (
    InvestigationSummary,
    SummaryObservationCategory,
)
from app.runtime.contracts import (
    InvestigationRun,
    RuntimeStatus,
    StopReason,
)
from app.schemas.evidence import EvidenceType
from tests.conftest import CASE_ID, INCIDENT_ID, START


@pytest.fixture
def real_summary(real_run: InvestigationRun, extractor: Any, summary_builder: Any) -> InvestigationSummary:
    extraction = extractor.extract(real_run)
    return summary_builder.build(real_run, extraction)


def test_summary_reports_run_metadata(
    real_run: InvestigationRun, real_summary: InvestigationSummary
) -> None:
    assert real_summary.incident_id == real_run.incident_id
    assert real_summary.case_id == CASE_ID
    assert real_summary.status is RuntimeStatus.COMPLETED
    assert real_summary.stop_reason is StopReason.COMPLETED
    assert real_summary.tool_call_count == len(real_run.tool_calls)
    assert real_summary.evidence_count == len(real_summary.evidence_ids)
    assert real_summary.generated_at == real_run.completed_at


def test_observations_distinguish_activity_from_knowledge(
    real_summary: InvestigationSummary,
) -> None:
    by_category = {
        category: real_summary.observations_of_category(category)
        for category in SummaryObservationCategory
    }

    assert len(by_category[SummaryObservationCategory.OBSERVED_ACTIVITY]) >= 10
    assert len(by_category[SummaryObservationCategory.REPUTATION_INTELLIGENCE]) == 1
    assert len(by_category[SummaryObservationCategory.CTI_KNOWLEDGE_REFERENCE]) == 1
    assert len(by_category[SummaryObservationCategory.ATTACK_KNOWLEDGE_REFERENCE]) == 2

    reputation = by_category[SummaryObservationCategory.REPUTATION_INTELLIGENCE][0]
    assert "203.0.113.47" in reputation.title
    assert "malicious" in reputation.title
    assert "reported as" in reputation.description
    assert "not an observation of activity" in reputation.description

    for observation in by_category[SummaryObservationCategory.ATTACK_KNOWLEDGE_REFERENCE]:
        assert "not a confirmed technique usage" in observation.description

    cti = by_category[SummaryObservationCategory.CTI_KNOWLEDGE_REFERENCE][0]
    assert "CTI-001" in cti.title
    assert "does not confirm that the described activity occurred here" in cti.description


def test_observations_reference_existing_evidence_of_matching_type(
    real_run: InvestigationRun, extractor: Any, real_summary: InvestigationSummary
) -> None:
    extraction = extractor.extract(real_run)
    evidence_by_id = {item.evidence_id: item for item in extraction.evidence}

    assert real_summary.observations
    for observation in real_summary.observations:
        assert observation.evidence_ids
        for evidence_id in observation.evidence_ids:
            assert evidence_id in evidence_by_id
            evidence = evidence_by_id[evidence_id]
            if observation.category is SummaryObservationCategory.REPUTATION_INTELLIGENCE:
                assert evidence.evidence_type is EvidenceType.IOC_REPUTATION
            elif observation.category is SummaryObservationCategory.CTI_KNOWLEDGE_REFERENCE:
                assert evidence.evidence_type is EvidenceType.THREAT_INTELLIGENCE
            elif observation.category is SummaryObservationCategory.ATTACK_KNOWLEDGE_REFERENCE:
                assert evidence.evidence_type is EvidenceType.ATTACK_KNOWLEDGE


def test_unlinked_knowledge_is_a_gap_not_an_observation(
    real_summary: InvestigationSummary,
) -> None:
    assert len(real_summary.unlinked_knowledge_evidence_ids) == 4
    unlinked = set(real_summary.unlinked_knowledge_evidence_ids)
    for observation in real_summary.observations:
        assert not unlinked.intersection(observation.evidence_ids)
    assert any(
        "without a case link" in gap and "not findings about this case" in gap
        for gap in real_summary.information_gaps
    )


def test_empty_queries_are_reported_as_gaps(real_summary: InvestigationSummary) -> None:
    gaps = " ".join(real_summary.information_gaps)

    assert "returned no matching events" in gaps
    assert "matched no file telemetry record" in gaps
    assert "found no record for the indicator" in gaps
    assert "Absence of matching data is not evidence of benign activity" in gaps
    assert "which is not a benign assessment" in gaps


def test_summary_contains_no_verdict(real_summary: InvestigationSummary) -> None:
    payload = json.loads(real_summary.model_dump_json())
    dumped = real_summary.model_dump_json().lower()

    assert "verdict" not in payload
    assert '"verdict"' not in dumped
    assert "confidence" not in payload
    # "benign" may only appear inside the explicit negations ("... is not evidence of
    # benign activity", "... which is not a benign assessment").
    assert dumped.count("benign") == dumped.count(
        "evidence of benign activity"
    ) + dumped.count("not a benign assessment")


def test_limitations_are_fixed_and_honest(real_summary: InvestigationSummary) -> None:
    assert len(real_summary.limitations) == 5
    text = " ".join(real_summary.limitations)

    assert "No verdict, severity, risk score or confidence is produced" in text
    assert "not proof that the described behaviour occurred" in text
    assert "never as evidence of benign activity" in text
    assert "Coverage is limited to the benchmark dataset" in text


def test_summary_is_deterministic(
    real_run: InvestigationRun, extractor: Any, summary_builder: Any
) -> None:
    extraction = extractor.extract(real_run)

    first = summary_builder.build(real_run, extraction)
    second = summary_builder.build(real_run, extraction)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_unknown_reputation_is_a_gap_without_a_conclusion(
    run_factory: Any,
    tool_call_factory: Any,
    tool_result_factory: Any,
    extractor: Any,
    summary_builder: Any,
) -> None:
    payload = {
        "indicator": "d1f68046f63004fe547db9f0b72f29c82a28de72da70601c909eabda75bf2ede",
        "found": True,
        "records": [
            {
                "indicator": "d1f68046f63004fe547db9f0b72f29c82a28de72da70601c909eabda75bf2ede",
                "indicator_type": "sha256",
                "reputation": "unknown",
                "confidence": 0.0,
                "source": "benchmark-community-feed",
            }
        ],
    }
    call = tool_call_factory(
        TOOL_LOOKUP_IOC_REPUTATION,
        {
            "indicator": "d1f68046f63004fe547db9f0b72f29c82a28de72da70601c909eabda75bf2ede"
        },
        index=1,
    )
    run = run_factory([(call, tool_result_factory(call, payload, index=1))])

    summary = summary_builder.build(run, extractor.extract(run))

    assert summary.evidence_count == 1
    assert any("as 'unknown'" in gap for gap in summary.information_gaps)
    observation = summary.observations_of_category(
        SummaryObservationCategory.REPUTATION_INTELLIGENCE
    )[0]
    assert "(unknown)" in observation.title
    assert "no assessment is available" in observation.description
    dumped = summary.model_dump_json().lower()
    assert dumped.count("benign") == dumped.count(
        "evidence of benign activity"
    ) + dumped.count("not a benign assessment")


def test_partial_failure_still_produces_a_summary(
    run_factory: Any,
    tool_call_factory: Any,
    tool_result_factory: Any,
    extractor: Any,
    summary_builder: Any,
) -> None:
    good_payload = {
        "case_id": CASE_ID,
        "items": [
            {
                "event_id": "EPE-999-001",
                "timestamp": "2026-03-02T09:11:52Z",
                "host": "ws-test-01",
                "user": "u.test",
                "event_type": "process_creation",
                "process_name": "powershell.exe",
                "metadata": {},
            }
        ],
        "count": 1,
    }
    good_call = tool_call_factory(TOOL_SEARCH_ENDPOINT, index=1)
    failing_call = tool_call_factory(TOOL_SEARCH_CTI, index=2)
    orphan_call = tool_call_factory(TOOL_SEARCH_CTI, index=3)
    run = run_factory(
        [
            (good_call, tool_result_factory(good_call, good_payload, index=1)),
            (
                failing_call,
                tool_result_factory(
                    failing_call,
                    None,
                    index=2,
                    success=False,
                    error="invalid arguments for tool 'search_cti': query: required",
                ),
            ),
            (orphan_call, tool_result_factory(orphan_call, {"cti_count": 0}, index=3)),
        ]
    )
    run = run.model_copy(
        update={
            "tool_results": run.tool_results[:2],
            "status": RuntimeStatus.FAILED,
            "stop_reason": StopReason.UNRECOVERABLE_TOOL_ERROR,
        }
    )

    summary = summary_builder.build(run, extractor.extract(run))

    assert summary.evidence_count == 1
    assert summary.observation_count == 1
    gaps = " ".join(summary.information_gaps)
    assert "invalid arguments for tool 'search_cti'" in gaps
    assert "produced no ToolResult (executor exception)" in gaps
    assert "results are partial" in gaps


def test_planner_failure_is_reported_as_a_gap(
    alert: Any, extractor: Any, summary_builder: Any
) -> None:
    run = InvestigationRun(
        incident_id=INCIDENT_ID,
        alert=alert,
        plan=None,
        tool_calls=[],
        tool_results=[],
        trajectory=[],
        status=RuntimeStatus.FAILED,
        stop_reason=StopReason.PLANNER_FAILED,
        started_at=START,
        completed_at=START,
    )

    summary = summary_builder.build(run, extractor.extract(run))

    assert summary.tool_call_count == 0
    assert summary.evidence_count == 0
    assert any("did not produce a plan" in gap for gap in summary.information_gaps)
    assert any(
        "No evidence could be extracted" in gap for gap in summary.information_gaps
    )


def test_budget_exhaustion_is_reported_as_partial(
    run_factory: Any,
    tool_call_factory: Any,
    tool_result_factory: Any,
    extractor: Any,
    summary_builder: Any,
) -> None:
    call = tool_call_factory(TOOL_SEARCH_CTI, index=1)
    run = run_factory(
        [(call, tool_result_factory(call, {"cti_count": 0, "technique_count": 0}, index=1))],
        status=RuntimeStatus.BUDGET_EXHAUSTED,
        stop_reason=StopReason.MAX_STEPS_EXCEEDED,
    )

    summary = summary_builder.build(run, extractor.extract(run))

    gaps = " ".join(summary.information_gaps)
    assert "status 'budget_exhausted'" in gaps
    assert "'max_steps_exceeded'" in gaps
    assert "matched no CTI record" in gaps
