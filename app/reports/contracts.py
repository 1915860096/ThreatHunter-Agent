"""Final report contracts for T08."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.benchmark.schemas import CaseId
from app.findings.contracts import SecurityFinding
from app.reporting.contracts import SummaryObservation
from app.runtime.contracts import RuntimeStatus, StopReason
from app.schemas.common import (
    EvidenceId,
    IncidentId,
    NonEmptyStr,
    ReportId,
    ToolCallId,
    ToolResultId,
    UtcDatetime,
)
from app.schemas.evidence import EvidenceType
from app.verdict.contracts import InvestigationVerdict


class EvidenceIndexEntry(BaseModel):
    """One row of the report's evidence index (audit trail)."""

    evidence_id: EvidenceId
    evidence_type: EvidenceType
    summary: NonEmptyStr
    tool_call_id: ToolCallId
    tool_result_id: ToolResultId
    raw_ref: NonEmptyStr
    reliability: float = Field(ge=0.0, le=1.0)
    source_count: int = Field(default=1, ge=1)
    additional_sources: list[str] = Field(default_factory=list)


class TraceRef(BaseModel):
    """Link from one agent decision to the tool call it produced."""

    decision_id: NonEmptyStr
    step_id: NonEmptyStr
    action: NonEmptyStr
    selected_tool: str | None = None
    validation_status: NonEmptyStr
    tool_call_id: ToolCallId | None = None
    mode: str | None = None


class FinalInvestigationReport(BaseModel):
    """Auditable, evidence-grounded final report of one investigation.

    ``methodology`` states which planning mode produced the run (live LLM,
    scripted rule-based client or deterministic planner) and which parts are
    deterministic, so the report never claims the investigation was LLM-free
    when it was not (or vice versa).
    """

    model_config = ConfigDict(extra="forbid")

    report_id: ReportId
    incident_id: IncidentId
    case_id: CaseId
    alert_summary: NonEmptyStr
    investigation_status: RuntimeStatus
    stop_reason: StopReason
    findings: list[SecurityFinding] = Field(default_factory=list)
    verdict: InvestigationVerdict
    observations: list[SummaryObservation] = Field(default_factory=list)
    information_gaps: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    methodology: list[str] = Field(default_factory=list)
    evidence_index: list[EvidenceIndexEntry] = Field(default_factory=list)
    trace_refs: list[TraceRef] = Field(default_factory=list)
    generated_at: UtcDatetime

    @model_validator(mode="after")
    def _validate_references(self) -> "FinalInvestigationReport":
        known = {entry.evidence_id for entry in self.evidence_index}
        for finding in self.findings:
            unknown = [item for item in finding.evidence_ids if item not in known]
            if unknown:
                raise ValueError(
                    f"finding {finding.finding_id} references unknown evidence: {unknown}"
                )
        for evidence_id in self.verdict.counter_evidence_ids:
            if evidence_id not in known:
                raise ValueError(f"verdict counter-evidence {evidence_id} is unknown")
        finding_ids = {finding.finding_id for finding in self.findings}
        unknown_findings = [
            item for item in self.verdict.supporting_finding_ids if item not in finding_ids
        ]
        if unknown_findings:
            raise ValueError(f"verdict references unknown findings: {unknown_findings}")
        return self
