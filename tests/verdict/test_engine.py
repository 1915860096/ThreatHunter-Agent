"""Tests for the explainable verdict rules."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.evidence.contracts import EvidenceExtractionResult
from app.findings import FindingEngine
from app.reporting import InvestigationSummary
from app.runtime.contracts import RuntimeStatus, StopReason
from app.verdict import (
    InvestigationVerdict,
    VerdictConfidence,
    VerdictDisposition,
    VerdictEngine,
)
from app.verdict.engine import (
    RULE_VERDICT_BENIGN,
    RULE_VERDICT_INCONCLUSIVE,
    RULE_VERDICT_MALICIOUS,
    RULE_VERDICT_SUSPICIOUS,
)
from tests.findings.conftest import (
    BENIGN_HASH,
    MALICIOUS_IP,
    attack_record,
    cti_record,
    dns_record,
    endpoint_record,
    file_record,
    network_record,
    payload_for,
    reputation_record,
)


def summarize(
    run: Any, extraction: EvidenceExtractionResult, gaps: list[str] | None = None
) -> InvestigationSummary:
    return InvestigationSummary(
        incident_id=extraction.incident_id,
        case_id=extraction.case_id,
        status=run.status,
        stop_reason=run.stop_reason,
        tool_call_count=len(run.tool_calls),
        evidence_count=extraction.evidence_count,
        observations=[],
        information_gaps=list(gaps or []),
        limitations=["T06 limitation"],
        evidence_type_counts=extraction.evidence_type_counts,
        evidence_ids=extraction.evidence_ids(),
        generated_at=run.completed_at,
    )


def verdict_of(
    *,
    run: Any,
    extraction: EvidenceExtractionResult,
    gaps: list[str] | None = None,
) -> InvestigationVerdict:
    findings = FindingEngine().build(extraction)
    return VerdictEngine().build(
        run=run,
        extraction=extraction,
        summary=summarize(run, extraction, gaps),
        findings=findings,
    )


def test_contract_requires_support_for_escalated_dispositions() -> None:
    with pytest.raises(ValidationError):
        InvestigationVerdict(
            incident_id="INC-000001",
            disposition=VerdictDisposition.MALICIOUS,
            confidence_level=VerdictConfidence.HIGH,
            rationale="because",
            rule_id="RULE-VERDICT-MAL-001",
        )

    built = InvestigationVerdict(
        incident_id="INC-000001",
        disposition=VerdictDisposition.INCONCLUSIVE,
        confidence_level=VerdictConfidence.LOW,
        rationale="not enough evidence",
        rule_id="RULE-VERDICT-INC-001",
    )
    assert built.is_escalated is False


def test_contract_forbids_unknown_fields_and_bad_finding_ids() -> None:
    with pytest.raises(ValidationError):
        InvestigationVerdict(
            incident_id="INC-000001",
            disposition=VerdictDisposition.SUSPICIOUS,
            confidence_level=VerdictConfidence.MEDIUM,
            rationale="because",
            supporting_finding_ids=["IOCF-000001"],
            rule_id="RULE-VERDICT-SUS-001",
        )

    with pytest.raises(ValidationError):
        InvestigationVerdict(
            incident_id="INC-000001",
            disposition=VerdictDisposition.INCONCLUSIVE,
            confidence_level=VerdictConfidence.LOW,
            rationale="because",
            probability=0.87,  # type: ignore[call-arg]
            rule_id="RULE-VERDICT-INC-001",
        )


def test_malicious_requires_a_linked_behaviour_finding(
    make_extraction: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    calls = [
        ("search_endpoint_events", payload_for("search_endpoint_events", endpoint_record())),
        ("search_network_activity", payload_for("search_network_activity", network_record(), dns_record())),
        ("lookup_ioc_reputation", payload_for("lookup_ioc_reputation", reputation_record())),
    ]
    extraction = make_extraction(calls)
    run = run_factory(
        [
            (
                tool_call_factory(tool, index=index),
                tool_result_factory(tool_call_factory(tool, index=index), payload, index=index),
            )
            for index, (tool, payload) in enumerate(calls, start=1)
        ]
    )

    verdict = verdict_of(run=run, extraction=extraction)

    assert verdict.disposition is VerdictDisposition.MALICIOUS
    assert verdict.confidence_level is VerdictConfidence.HIGH
    assert verdict.rule_id == RULE_VERDICT_MALICIOUS
    assert len(verdict.supporting_finding_ids) >= 2


def test_malicious_indicator_without_linked_behaviour_is_suspicious(
    make_extraction: Any, run_factory: Any
) -> None:
    # The malicious IP is only ever seen as a DNS query string from a
    # non-interpreter process, so no behaviour finding is linked to it.
    dns = dns_record(process_name="chrome.exe", query="203.0.113.47")
    calls = [
        ("search_network_activity", payload_for("search_network_activity", dns)),
        ("lookup_ioc_reputation", payload_for("lookup_ioc_reputation", reputation_record())),
    ]
    extraction = make_extraction(calls)
    run = run_factory([])

    verdict = verdict_of(run=run, extraction=extraction)

    assert verdict.disposition is VerdictDisposition.SUSPICIOUS
    assert verdict.confidence_level is VerdictConfidence.MEDIUM
    assert verdict.rule_id == RULE_VERDICT_SUSPICIOUS


def test_medium_findings_without_indicator_are_suspicious(
    make_extraction: Any, run_factory: Any
) -> None:
    flow = network_record()
    extraction = make_extraction(
        [("search_network_activity", payload_for("search_network_activity", flow))]
    )

    verdict = verdict_of(run=run_factory([]), extraction=extraction)

    assert verdict.disposition is VerdictDisposition.SUSPICIOUS
    assert verdict.rule_id == RULE_VERDICT_SUSPICIOUS


def test_observed_allowlist_match_is_benign(make_extraction: Any, run_factory: Any) -> None:
    calls = [
        ("lookup_file_reputation", payload_for(
            "lookup_file_reputation",
            file_record(path="C:\\Program Files\\CorpIT\\tool.exe", file_name="tool.exe", sha256=BENIGN_HASH, signed=True),
            reputation_record(indicator=BENIGN_HASH, indicator_type="sha256", reputation="benign", source="benchmark-internal-allowlist"),
        )),
    ]
    extraction = make_extraction(calls)

    verdict = verdict_of(run=run_factory([]), extraction=extraction)

    assert verdict.disposition is VerdictDisposition.BENIGN
    assert verdict.rule_id == RULE_VERDICT_BENIGN
    assert verdict.counter_evidence_ids == []


def test_knowledge_only_benign_reputation_is_not_benign(
    make_extraction: Any, run_factory: Any
) -> None:
    calls = [
        ("lookup_ioc_reputation", payload_for(
            "lookup_ioc_reputation",
            reputation_record(indicator=BENIGN_HASH, indicator_type="sha256", reputation="benign"),
        )),
    ]
    extraction = make_extraction(calls)

    verdict = verdict_of(run=run_factory([]), extraction=extraction)

    assert verdict.disposition is VerdictDisposition.INCONCLUSIVE
    assert verdict.disposition is not VerdictDisposition.BENIGN


def test_unknown_reputation_and_empty_results_are_never_benign(
    make_extraction: Any, run_factory: Any
) -> None:
    calls = [
        ("search_endpoint_events", payload_for("search_endpoint_events")),
        ("lookup_ioc_reputation", payload_for("lookup_ioc_reputation", reputation_record(reputation="unknown", confidence=0.0))),
    ]
    extraction = make_extraction(calls)

    verdict = verdict_of(run=run_factory([]), extraction=extraction)

    assert verdict.disposition is VerdictDisposition.INCONCLUSIVE
    assert verdict.confidence_level is VerdictConfidence.LOW
    assert verdict.rule_id == RULE_VERDICT_INCONCLUSIVE


def test_no_evidence_at_all_is_inconclusive(run_factory: Any) -> None:
    extraction = EvidenceExtractionResult(incident_id="INC-000001", case_id="CASE-001")

    verdict = verdict_of(run=run_factory([]), extraction=extraction)

    assert verdict.disposition is VerdictDisposition.INCONCLUSIVE
    assert verdict.supporting_finding_ids == []


def test_cti_only_investigation_is_never_malicious(
    make_extraction: Any, run_factory: Any
) -> None:
    extraction = make_extraction(
        [("search_cti", payload_for("search_cti", cti_record(), attack_record()))]
    )

    verdict = verdict_of(run=run_factory([]), extraction=extraction)

    assert verdict.disposition is VerdictDisposition.INCONCLUSIVE
    assert verdict.disposition is not VerdictDisposition.MALICIOUS


def test_incomplete_investigation_keeps_a_partial_coverage_limitation(
    make_extraction: Any, run_factory: Any
) -> None:
    calls = [
        ("search_endpoint_events", payload_for("search_endpoint_events", endpoint_record())),
        ("search_network_activity", payload_for("search_network_activity", network_record(), dns_record())),
        ("lookup_ioc_reputation", payload_for("lookup_ioc_reputation", reputation_record())),
    ]
    extraction = make_extraction(calls)
    run = run_factory(
        [],
        status=RuntimeStatus.BUDGET_EXHAUSTED,
        stop_reason=StopReason.MAX_TOOL_CALLS_EXCEEDED,
    )

    verdict = verdict_of(run=run, extraction=extraction)

    assert verdict.disposition is VerdictDisposition.MALICIOUS
    assert verdict.confidence_level is VerdictConfidence.MEDIUM
    assert any("partial" in item for item in verdict.limitations)


def test_uncompleted_run_without_strong_support_stays_suspicious(
    make_extraction: Any, run_factory: Any
) -> None:
    flow = network_record()
    extraction = make_extraction(
        [("search_network_activity", payload_for("search_network_activity", flow))]
    )
    run = run_factory(
        [], status=RuntimeStatus.FAILED, stop_reason=StopReason.PLANNER_FAILED
    )

    verdict = verdict_of(run=run, extraction=extraction)

    assert verdict.disposition is VerdictDisposition.SUSPICIOUS
    assert verdict.confidence_level in (VerdictConfidence.LOW, VerdictConfidence.MEDIUM)


def test_confidence_is_a_level_not_a_probability(
    make_extraction: Any, run_factory: Any
) -> None:
    calls = [
        ("search_endpoint_events", payload_for("search_endpoint_events", endpoint_record())),
        ("search_network_activity", payload_for("search_network_activity", network_record(), dns_record())),
        ("lookup_ioc_reputation", payload_for("lookup_ioc_reputation", reputation_record())),
    ]
    verdict = verdict_of(run=run_factory([]), extraction=make_extraction(calls))

    payload = verdict.model_dump(mode="json")
    assert payload["confidence_level"] in ("low", "medium", "high")
    assert "confidence" not in payload
    assert "probability" not in payload
    assert "calibrated probability" in verdict.limitations[0]


def test_information_gaps_are_carried_into_the_verdict(
    make_extraction: Any, run_factory: Any
) -> None:
    extraction = make_extraction(
        [("search_endpoint_events", payload_for("search_endpoint_events"))]
    )

    verdict = verdict_of(
        run=run_factory([]),
        extraction=extraction,
        gaps=["Endpoint search returned no matching events."],
    )

    assert verdict.information_gaps == ["Endpoint search returned no matching events."]
