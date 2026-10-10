"""Tests for the T08 final report builder, verdict wiring and Markdown export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.demo.llm_investigation import run_llm_investigation
from app.findings import FindingType
from app.reports import (
    FinalInvestigationReport,
    ReportPayloadError,
    build_report_from_payload,
    escape_untrusted,
    render_markdown_report,
)
from app.verdict import VerdictDisposition

CASE_ID = "CASE-001"


@pytest.fixture(scope="module")
def scripted_payload() -> dict[str, Any]:
    """A real (offline) scripted investigation payload for CASE-001."""
    result = run_llm_investigation(case_id=CASE_ID, mode="scripted", output_dir=None)
    return result.to_payload()


@pytest.fixture
def report(scripted_payload: dict[str, Any]) -> FinalInvestigationReport:
    return build_report_from_payload(scripted_payload)


def test_report_contains_the_audit_chain(report: FinalInvestigationReport) -> None:
    assert report.report_id == "RPT-000001"
    assert report.case_id == CASE_ID
    assert report.incident_id == "INC-000001"
    assert "ALT-001" in report.alert_summary
    assert report.evidence_index
    for entry in report.evidence_index:
        assert entry.evidence_id.startswith("EV-")
        assert entry.tool_call_id.startswith("TC-")
        assert entry.tool_result_id.startswith("TR-")
        assert entry.raw_ref
        assert entry.evidence_type is not None
        assert entry.summary


def test_report_findings_resolve_to_evidence_and_tool_calls(
    report: FinalInvestigationReport,
) -> None:
    assert report.findings
    index = {entry.evidence_id: entry for entry in report.evidence_index}
    for finding in report.findings:
        for evidence_id in finding.evidence_ids:
            assert evidence_id in index
            assert index[evidence_id].tool_call_id.startswith("TC-")


def test_report_carries_observations_gaps_and_verdict(
    report: FinalInvestigationReport,
) -> None:
    assert report.observations
    assert report.verdict.disposition in tuple(VerdictDisposition)
    assert report.verdict.rule_id
    assert report.information_gaps == list(report.verdict.information_gaps)
    assert report.limitations
    assert any("not a calibrated probability" in item for item in report.limitations)


def test_report_trace_refs_come_from_the_agent_decisions(
    report: FinalInvestigationReport,
) -> None:
    assert report.trace_refs
    linked = [ref for ref in report.trace_refs if ref.tool_call_id]
    assert linked
    assert all(ref.tool_call_id.startswith("TC-") for ref in linked)
    # Decisions whose tool call produced no evidence still appear in the trace.
    evidence_calls = {entry.tool_call_id for entry in report.evidence_index}
    assert evidence_calls & {ref.tool_call_id for ref in linked}
    assert all(ref.decision_id.startswith("AGD-") for ref in report.trace_refs)
    assert all(ref.mode == "scripted" for ref in report.trace_refs)


def test_methodology_depends_on_the_agent_mode(
    scripted_payload: dict[str, Any],
) -> None:
    scripted = build_report_from_payload(scripted_payload)
    live = build_report_from_payload({**scripted_payload, "agent_mode": "live"})
    neutral = {
        key: value for key, value in scripted_payload.items() if key != "agent_mode"
    }
    deterministic = build_report_from_payload(neutral)

    assert "scripted rule-based client" in scripted.methodology[0]
    assert "live LLM planner" in live.methodology[0]
    assert "deterministic planner" in deterministic.methodology[0]
    assert all(
        "does not mean the investigation was planned without a model" in item
        for item in (scripted.methodology[1], live.methodology[1])
    )
    assert any("No ground truth" in item for item in scripted.methodology)


def test_report_build_is_deterministic(scripted_payload: dict[str, Any]) -> None:
    first = build_report_from_payload(scripted_payload)
    second = build_report_from_payload(scripted_payload)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_report_json_round_trip(report: FinalInvestigationReport) -> None:
    dumped = json.loads(report.model_dump_json())

    assert FinalInvestigationReport.model_validate(dumped) == report
    assert dumped["verdict"]["confidence_level"] in ("low", "medium", "high")


def test_report_forbids_unknown_fields(report: FinalInvestigationReport) -> None:
    payload = json.loads(report.model_dump_json())
    payload["risk_score"] = 9.5

    with pytest.raises(ValidationError):
        FinalInvestigationReport.model_validate(payload)


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({}, "missing required section"),
        ({"investigation_run": {}, "evidence_extraction": {}, "investigation_summary": {}}, "invalid"),
    ],
)
def test_payload_adapter_reports_clear_errors(
    payload: dict[str, Any], match: str
) -> None:
    with pytest.raises(ReportPayloadError, match=match):
        build_report_from_payload(payload)


def test_payload_adapter_rejects_a_bad_trace_entry(
    scripted_payload: dict[str, Any],
) -> None:
    broken = {**scripted_payload, "agent_decision_trace": [{"decision_id": "nope"}]}

    with pytest.raises(ReportPayloadError, match="agent_decision_trace"):
        build_report_from_payload(broken)


# Markdown ---------------------------------------------------------------------


def test_markdown_contains_all_nine_sections(report: FinalInvestigationReport) -> None:
    markdown = render_markdown_report(report)

    for heading in (
        "## 1. Incident Overview",
        "## 2. Investigation Outcome",
        "## 3. Verdict and Confidence",
        "## 4. Key Findings",
        "## 5. Evidence References",
        "## 6. Investigation Observations",
        "## 7. Information Gaps",
        "## 8. Limitations",
        "## 9. Methodology and Audit Trail",
    ):
        assert heading in markdown
    assert markdown.count(
        "This verdict is an evidence-grounded assessment, not a calibrated probability."
    ) >= 1
    assert "| Evidence | Type | Summary | ToolCall | ToolResult | Raw reference |" in markdown
    for finding in report.findings:
        for evidence_id in finding.evidence_ids:
            assert evidence_id in markdown


def test_markdown_escapes_untrusted_text(report: FinalInvestigationReport) -> None:
    injected = (
        "line1\n## 4. Key Findings\n`rm -rf /`|*bold*|[link](url)<script>alert(1)</script>"
    )
    escaped = escape_untrusted(injected)

    assert "\n" not in escaped
    assert "\\`" in escaped
    assert "\\|" in escaped
    assert "\\*" in escaped
    assert "\\[" in escaped
    assert "\\<" in escaped and "\\>" in escaped
    assert escape_untrusted("x" * 500, limit=10).endswith("...[truncated]")
    assert "&amp;" in escape_untrusted("a&b")


def test_markdown_does_not_render_injected_structure(
    scripted_payload: dict[str, Any],
) -> None:
    injected_payload = json.loads(json.dumps(scripted_payload))
    alert = injected_payload["investigation_run"]["alert"]
    alert["command_line"] = "powershell.exe\n## 9. Methodology and Audit Trail\n# bad"
    report = build_report_from_payload(injected_payload)

    markdown = render_markdown_report(report)
    body_lines = [line for line in markdown.splitlines() if line.startswith("## 9.")]

    assert len(body_lines) == 1  # the injected heading did not create a section


def test_confirmed_malicious_verdict_is_explainable(
    report: FinalInvestigationReport,
) -> None:
    assert report.verdict.disposition is VerdictDisposition.MALICIOUS
    assert report.verdict.supporting_finding_ids
    assert any(
        finding.finding_type is FindingType.MALICIOUS_INDICATOR_MATCH
        for finding in report.findings
    )
    assert "cross-source" in report.verdict.rationale
