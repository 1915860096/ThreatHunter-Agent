"""Summary contracts for T06.

``InvestigationSummary`` carries observations, information gaps and
limitations - and deliberately no verdict, severity or confidence field. Every
observation must reference evidence that exists in the extraction result.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.benchmark.schemas import CaseId
from app.runtime.contracts import RuntimeStatus, StopReason
from app.schemas.common import (
    EvidenceIdListNonEmpty,
    IncidentId,
    NonEmptyStr,
    UtcDatetime,
)


class SummaryObservationCategory(StrEnum):
    """What kind of statement an observation makes."""

    OBSERVED_ACTIVITY = "observed_activity"
    REPUTATION_INTELLIGENCE = "reputation_intelligence"
    CTI_KNOWLEDGE_REFERENCE = "cti_knowledge_reference"
    ATTACK_KNOWLEDGE_REFERENCE = "attack_knowledge_reference"


class SummaryObservation(BaseModel):
    """A factual statement backed by at least one evidence id."""

    model_config = ConfigDict(extra="forbid")

    category: SummaryObservationCategory
    title: NonEmptyStr
    description: NonEmptyStr
    evidence_ids: EvidenceIdListNonEmpty


class InvestigationSummary(BaseModel):
    """Deterministic summary of one investigation.

    ``evidence_ids`` lists every evidence id of the extraction result, so the
    contract can prove that each observation only references existing evidence.
    ``unlinked_knowledge_evidence_ids`` lists knowledge records that no case
    indicator ties to this investigation.
    """

    model_config = ConfigDict(extra="forbid")

    incident_id: IncidentId
    case_id: CaseId
    status: RuntimeStatus
    stop_reason: StopReason
    tool_call_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)
    observations: list[SummaryObservation] = Field(default_factory=list)
    information_gaps: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    evidence_type_counts: dict[str, int] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    unlinked_knowledge_evidence_ids: list[str] = Field(default_factory=list)
    generated_at: UtcDatetime

    @model_validator(mode="after")
    def _validate_observations(self) -> "InvestigationSummary":
        if len(self.evidence_ids) != self.evidence_count:
            raise ValueError("evidence_ids must list exactly the extracted evidence")

        known = set(self.evidence_ids)
        for observation in self.observations:
            unknown = [item for item in observation.evidence_ids if item not in known]
            if unknown:
                raise ValueError(
                    f"observation {observation.title!r} references unknown evidence: {unknown}"
                )
        for evidence_id in self.unlinked_knowledge_evidence_ids:
            if evidence_id not in known:
                raise ValueError(f"unlinked knowledge id {evidence_id} is not part of the run")
        return self

    @property
    def observation_count(self) -> int:
        """Number of observations."""
        return len(self.observations)

    @property
    def gap_count(self) -> int:
        """Number of recorded information gaps."""
        return len(self.information_gaps)

    def observations_of_category(
        self, category: SummaryObservationCategory
    ) -> list[SummaryObservation]:
        """Observations of one category, in order."""
        return [item for item in self.observations if item.category is category]
