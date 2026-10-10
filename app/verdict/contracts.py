"""Verdict contracts for T08.

The disposition reuses the frozen T02 ``InvestigationVerdict`` enum (imported
here as :data:`VerdictDisposition`) instead of redefining it.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Annotated, Final

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.schemas.common import EvidenceIdList, IncidentId, NonEmptyStr, validate_id
from app.schemas.report import InvestigationVerdict as VerdictDisposition

VERDICT_FINDING_ID_PREFIX: Final[str] = "FIND-"


class VerdictConfidence(StrEnum):
    """Explainable confidence level (never a calibrated probability)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def _verdict_finding_id(value: str) -> str:
    return validate_id(value, VERDICT_FINDING_ID_PREFIX, "supporting_finding_id")


VerdictFindingIds = Annotated[list[str], AfterValidator(lambda values: [_verdict_finding_id(v) for v in values])]


class InvestigationVerdict(BaseModel):
    """Evidence-grounded disposition of one investigation.

    ``supporting_finding_ids`` lists the findings the disposition rests on,
    ``counter_evidence_ids`` the evidence that argues against it (for example an
    observed allow-list match while the disposition is malicious).
    """

    model_config = ConfigDict(extra="forbid")

    incident_id: IncidentId
    disposition: VerdictDisposition
    confidence_level: VerdictConfidence
    rationale: NonEmptyStr
    supporting_finding_ids: VerdictFindingIds = Field(default_factory=list)
    counter_evidence_ids: EvidenceIdList = Field(default_factory=list)
    information_gaps: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    rule_id: NonEmptyStr

    @model_validator(mode="after")
    def _validate_support(self) -> "InvestigationVerdict":
        if self.disposition in (
            VerdictDisposition.MALICIOUS,
            VerdictDisposition.SUSPICIOUS,
        ) and not self.supporting_finding_ids:
            raise ValueError(
                "a malicious or suspicious disposition must reference at least one finding"
            )
        if len(set(self.supporting_finding_ids)) != len(self.supporting_finding_ids):
            raise ValueError("supporting_finding_ids must not contain duplicates")
        return self

    @property
    def is_escalated(self) -> bool:
        """True when the disposition is malicious or suspicious."""
        return self.disposition in (
            VerdictDisposition.MALICIOUS,
            VerdictDisposition.SUSPICIOUS,
        )
