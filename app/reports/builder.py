"""Deterministic final report builder and offline payload adapter (T08).

``build_report_from_payload`` is the Replay adapter: it accepts the JSON
produced by the T06/T07 demo CLIs (``investigation_run``,
``evidence_extraction``, ``investigation_summary`` plus the optional
``agent_decision_trace`` / ``agent_mode`` sections), re-validates every section
with the frozen T02-T07 models and rebuilds findings, verdict and report -
without re-running the agent, calling a tool or contacting a model.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from pydantic import ValidationError

from app.agents.decision_trace import AgentDecisionTrace
from app.evidence.contracts import EvidenceExtractionResult
from app.findings.contracts import SecurityFinding
from app.findings.engine import FindingEngine
from app.reports.contracts import (
    EvidenceIndexEntry,
    FinalInvestigationReport,
    TraceRef,
)
from app.reporting.contracts import InvestigationSummary
from app.runtime.contracts import InvestigationRun
from app.verdict.contracts import InvestigationVerdict
from app.verdict.engine import VerdictEngine

REPORT_ID: Final[str] = "RPT-000001"

METHOD_LIVE_NOTE: Final[str] = (
    "The investigation itself was planned by a live LLM planner (agent_mode=live); findings, "
    "verdict and this report are deterministic rule applications over the recorded evidence."
)
METHOD_SCRIPTED_NOTE: Final[str] = (
    "The investigation was planned by the scripted rule-based client (agent_mode=scripted); it "
    "validates the integration and is not a language model. Findings, verdict and this report "
    "are deterministic rule applications over the recorded evidence."
)
METHOD_DETERMINISTIC_NOTE: Final[str] = (
    "The investigation was planned by the deterministic planner; findings, verdict and this "
    "report are deterministic rule applications over the recorded evidence."
)
METHOD_T06_LIMITATION_CLARIFICATION: Final[str] = (
    "The T06 summary limitation about 'no LLM' describes the deterministic summary/evidence "
    "layer only; it does not mean the investigation was planned without a model."
)


class ReportPayloadError(ValueError):
    """Raised when an investigation payload cannot be turned into a report."""


@dataclass(frozen=True)
class FinalReportBuilder:
    """Builds :class:`~app.reports.contracts.FinalInvestigationReport` values."""

    finding_engine: FindingEngine
    verdict_engine: VerdictEngine
    report_id: str = REPORT_ID

    @classmethod
    def default(cls) -> "FinalReportBuilder":
        """Return a builder with the standard T08 engines."""
        return cls(finding_engine=FindingEngine(), verdict_engine=VerdictEngine())

    def build(
        self,
        *,
        run: InvestigationRun,
        extraction: EvidenceExtractionResult,
        summary: InvestigationSummary,
        case_id: str | None = None,
        decision_trace: Sequence[AgentDecisionTrace] = (),
        agent_mode: str | None = None,
        generated_at: datetime | None = None,
    ) -> FinalInvestigationReport:
        """Return the final report of one finished investigation."""
        findings = self.finding_engine.build(extraction)
        verdict = self.verdict_engine.build(
            run=run, extraction=extraction, summary=summary, findings=findings
        )
        return FinalInvestigationReport(
            report_id=self.report_id,
            incident_id=run.incident_id,
            case_id=case_id or summary.case_id,
            alert_summary=_alert_summary(run),
            investigation_status=run.status,
            stop_reason=run.stop_reason,
            findings=findings,
            verdict=verdict,
            observations=list(summary.observations),
            information_gaps=list(summary.information_gaps),
            limitations=_limitations(summary, verdict, findings),
            methodology=_methodology(agent_mode),
            evidence_index=self._evidence_index(extraction),
            trace_refs=_trace_refs(decision_trace),
            generated_at=generated_at or run.completed_at,
        )

    @staticmethod
    def _evidence_index(extraction: EvidenceExtractionResult) -> list[EvidenceIndexEntry]:
        entries: list[EvidenceIndexEntry] = []
        for item in extraction.evidence:
            references = extraction.sources_of(item.evidence_id)
            primary = item.provenance
            entries.append(
                EvidenceIndexEntry(
                    evidence_id=item.evidence_id,
                    evidence_type=item.evidence_type,
                    summary=item.summary,
                    tool_call_id=primary.tool_call_id,
                    tool_result_id=primary.tool_result_id,
                    raw_ref=primary.raw_ref or "",
                    reliability=item.reliability,
                    source_count=max(len(references), 1),
                    additional_sources=[
                        f"{reference.tool_call_id}/{reference.tool_result_id}"
                        for reference in references[1:]
                    ],
                )
            )
        return entries


def build_report_from_payload(
    payload: Mapping[str, Any],
    *,
    case_id: str | None = None,
    builder: FinalReportBuilder | None = None,
) -> FinalInvestigationReport:
    """Rebuild a final report from a T06/T07 investigation payload."""
    if not isinstance(payload, Mapping):
        raise ReportPayloadError("payload must be a JSON object")
    sections = ("investigation_run", "evidence_extraction", "investigation_summary")
    missing = [name for name in sections if name not in payload]
    if missing:
        raise ReportPayloadError(
            "payload is missing required section(s): " + ", ".join(missing)
        )

    run = _validate(InvestigationRun, payload["investigation_run"], "investigation_run")
    extraction = _validate(
        EvidenceExtractionResult, payload["evidence_extraction"], "evidence_extraction"
    )
    summary = _validate(
        InvestigationSummary, payload["investigation_summary"], "investigation_summary"
    )
    trace: list[AgentDecisionTrace] = []
    for index, entry in enumerate(payload.get("agent_decision_trace") or []):
        trace.append(
            _validate(AgentDecisionTrace, entry, f"agent_decision_trace[{index}]")
        )

    resolved_case_id = case_id or payload.get("case_id") or summary.case_id
    agent_mode = payload.get("agent_mode")
    engine = builder or FinalReportBuilder.default()
    return engine.build(
        run=run,
        extraction=extraction,
        summary=summary,
        case_id=str(resolved_case_id),
        decision_trace=trace,
        agent_mode=str(agent_mode) if agent_mode else None,
    )


def _validate(model: type[Any], data: Any, section: str) -> Any:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        first = exc.errors(include_url=False, include_input=False)[:1]
        detail = "; ".join(
            f"{'.'.join(str(part) for part in issue['loc']) or '<root>'}: {issue['msg']}"
            for issue in first
        )
        raise ReportPayloadError(f"section {section} is invalid: {detail}") from exc


def _alert_summary(run: InvestigationRun) -> str:
    alert = run.alert
    parts = [
        f"{alert.severity.value} '{alert.event_type}' alert {alert.alert_id}",
        f"source {alert.source}",
    ]
    if alert.host:
        parts.append(f"host {alert.host}")
    if alert.user:
        parts.append(f"user {alert.user}")
    if alert.process_name:
        parts.append(f"process {alert.process_name}")
    if alert.dst_ip:
        parts.append(f"destination {alert.dst_ip}")
    return ", ".join(parts) + "."


def _limitations(
    summary: InvestigationSummary,
    verdict: InvestigationVerdict,
    findings: list[SecurityFinding],
) -> list[str]:
    limitations: list[str] = list(summary.limitations)
    limitations.extend(verdict.limitations)
    for finding in findings:
        limitations.extend(finding.limitations)
    return list(dict.fromkeys(limitations))


def _methodology(agent_mode: str | None) -> list[str]:
    mode = (agent_mode or "").strip().lower()
    if mode == "live":
        planning = METHOD_LIVE_NOTE
    elif mode == "scripted":
        planning = METHOD_SCRIPTED_NOTE
    else:
        planning = METHOD_DETERMINISTIC_NOTE
    return [
        planning,
        METHOD_T06_LIMITATION_CLARIFICATION,
        (
            "Tool execution: tool calls are created by the T05 investigation runtime under the "
            "step tool allow-list and executed by the T04 executor against the benchmark "
            "telemetry; the model never runs a tool directly."
        ),
        (
            "Evidence extraction (T06) and finding/verdict rules (T08) are deterministic and "
            "offline: findings reference only evidence ids that exist in the extraction result, "
            "and every evidence item resolves to a tool call, a tool result and a raw record."
        ),
        (
            "The verdict confidence is an explainable low/medium/high level derived from rule "
            "matches and investigation completeness - not a calibrated probability."
        ),
        "No ground truth, benchmark answer key or evaluation label was read by any T08 component.",
    ]


def _trace_refs(decisions: Sequence[AgentDecisionTrace]) -> list[TraceRef]:
    return [
        TraceRef(
            decision_id=entry.decision_id,
            step_id=entry.step_id or "STEP-UNKNOWN",
            action=entry.action,
            selected_tool=entry.selected_tool,
            validation_status=entry.validation_status,
            tool_call_id=entry.tool_call_id,
            mode=entry.mode,
        )
        for entry in decisions
    ]
