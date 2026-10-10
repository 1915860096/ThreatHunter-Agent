"""T06 evidence contracts: the extraction result and its multi-source index.

The frozen T02 ``EvidenceProvenance`` describes exactly one source, so the
multi-source view lives here instead of being pushed into T02: ``Evidence``
keeps its primary provenance while ``EvidenceExtractionResult.sources`` maps
each evidence id to *every* tool occurrence the raw record was seen through.

All lists and dicts use ``default_factory``; ordering is produced
deterministically by the extractor.
"""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field, model_validator

from app.benchmark.schemas import CaseId
from app.schemas.common import (
    EvidenceId,
    IncidentId,
    NonEmptyStr,
    ToolCallId,
    ToolResultId,
)
from app.schemas.evidence import Evidence, EvidenceSourceType, EvidenceType


class EvidenceSourceReference(BaseModel):
    """One raw-record occurrence behind an evidence item.

    ``record_id`` is the stable identity of the record inside its dataset file:
    the T03 record id where the schema has one (``EPE-…``, ``NET-…``, ``DNS-…``,
    ``FILE-…``, ``CTI-…``, ``T…``) and a stable composite key for knowledge
    records without an id column (IOC reputation).
    """

    source_type: EvidenceSourceType = EvidenceSourceType.TOOL
    source_name: NonEmptyStr
    tool_call_id: ToolCallId
    tool_result_id: ToolResultId
    record_id: NonEmptyStr
    raw_ref: NonEmptyStr
    source_fields: list[str] = Field(default_factory=list)


class EvidenceExtractionResult(BaseModel):
    """Deterministic evidence view of one investigation run.

    ``evidence`` holds deduplicated T02 evidence; ``sources`` maps every
    evidence id to all tool occurrences that observed the same raw record, in a
    stable order. ``candidate_count`` counts raw records seen *before*
    deduplication, so ``candidate_count - len(evidence)`` is the number of
    duplicate hits. ``processed_tool_result_ids`` lists the tool results whose
    payload was inspected (successful or not).
    """

    incident_id: IncidentId
    case_id: CaseId
    evidence: list[Evidence] = Field(default_factory=list)
    sources: dict[str, list[EvidenceSourceReference]] = Field(default_factory=dict)
    processed_tool_result_ids: list[ToolResultId] = Field(default_factory=list)
    candidate_count: int = Field(default=0, ge=0)
    extraction_warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_source_index(self) -> "EvidenceExtractionResult":
        evidence_ids = {item.evidence_id for item in self.evidence}
        if len(evidence_ids) != len(self.evidence):
            raise ValueError("evidence ids must be unique within an extraction result")

        indexed = set(self.sources)
        if indexed != evidence_ids:
            missing = sorted(evidence_ids - indexed)
            unknown = sorted(indexed - evidence_ids)
            raise ValueError(
                f"sources must cover every evidence id exactly once; missing={missing}, "
                f"unknown={unknown}"
            )
        if any(not references for references in self.sources.values()):
            raise ValueError("every evidence id must have at least one source reference")
        return self

    @property
    def evidence_count(self) -> int:
        """Number of deduplicated evidence items."""
        return len(self.evidence)

    @property
    def duplicate_hit_count(self) -> int:
        """Raw records seen more than once (candidate count minus evidence count)."""
        return max(self.candidate_count - self.evidence_count, 0)

    @property
    def source_reference_count(self) -> int:
        """Total number of preserved source references."""
        return sum(len(references) for references in self.sources.values())

    @property
    def evidence_type_counts(self) -> dict[str, int]:
        """Evidence counts per :class:`~app.schemas.evidence.EvidenceType`."""
        counts = Counter(item.evidence_type.value for item in self.evidence)
        return {name: counts[name] for name in sorted(counts)}

    def evidence_ids(self) -> list[str]:
        """Evidence ids in extraction order."""
        return [item.evidence_id for item in self.evidence]

    def evidence_of_type(self, evidence_type: EvidenceType) -> list[Evidence]:
        """Evidence items of one type, in extraction order."""
        return [item for item in self.evidence if item.evidence_type is evidence_type]

    def sources_of(self, evidence_id: EvidenceId) -> list[EvidenceSourceReference]:
        """All source references of one evidence id."""
        return list(self.sources.get(evidence_id, []))
