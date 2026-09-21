"""Investigation report: the final, evidence-backed conclusion."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import (
    AlertId,
    Confidence,
    EvidenceIdList,
    IncidentId,
    NonEmptyStr,
    ReportId,
    UtcDatetime,
)
from app.schemas.findings import AttackTechniqueFinding, IOCFinding


class InvestigationVerdict(StrEnum):
    """Overall conclusion of an investigation."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class RecommendationPriority(StrEnum):
    """Priority of a recommended follow-up action."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimelineEvent(BaseModel):
    """One entry of the reconstructed incident timeline."""

    timestamp: UtcDatetime
    description: NonEmptyStr
    evidence_ids: EvidenceIdList = Field(default_factory=list)


class Recommendation(BaseModel):
    """A follow-up action suggested by the report."""

    action: NonEmptyStr
    priority: RecommendationPriority
    rationale: NonEmptyStr
    evidence_ids: EvidenceIdList = Field(default_factory=list)


class InvestigationReport(BaseModel):
    """Final report for one alert.

    ``confidence`` expresses how strongly the referenced evidence supports the
    verdict; it is not computed here. A ``malicious`` or ``suspicious`` verdict
    must be backed by at least one evidence item, while an ``inconclusive``
    verdict may legitimately have none.
    """

    report_id: ReportId
    incident_id: IncidentId
    alert_id: AlertId
    verdict: InvestigationVerdict
    confidence: Confidence
    summary: NonEmptyStr
    iocs: list[IOCFinding] = Field(default_factory=list)
    attack_techniques: list[AttackTechniqueFinding] = Field(default_factory=list)
    evidence_ids: EvidenceIdList = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    generated_at: UtcDatetime

    @model_validator(mode="after")
    def _validate_verdict_is_evidence_backed(self) -> "InvestigationReport":
        if (
            self.verdict
            in (InvestigationVerdict.MALICIOUS, InvestigationVerdict.SUSPICIOUS)
            and not self.evidence_ids
        ):
            raise ValueError(
                "evidence_ids must reference at least one evidence item when "
                "verdict is 'malicious' or 'suspicious'"
            )
        return self
