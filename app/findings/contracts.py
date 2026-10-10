"""Finding contracts for T08.

``finding_id`` uses a T08-owned ``FIND-`` prefix (the frozen T02 ``FindingId``
alias is reserved for ``IOCF-`` IOC findings), so a local annotated type is
built from the shared T02 ``validate_id`` helper instead of touching T02.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Annotated, Final

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.schemas.common import (
    EvidenceIdListNonEmpty,
    IncidentId,
    NonEmptyStr,
    validate_id,
)

FINDING_ID_PREFIX: Final[str] = "FIND-"


class FindingType(StrEnum):
    """Category of a T08 finding."""

    SUSPICIOUS_PROCESS_EXECUTION = "suspicious_process_execution"
    SUSPICIOUS_FILE_ARTIFACT = "suspicious_file_artifact"
    SUSPICIOUS_NETWORK_ACTIVITY = "suspicious_network_activity"
    MALICIOUS_INDICATOR_MATCH = "malicious_indicator_match"
    CORRELATED_ATTACK_PATTERN = "correlated_attack_pattern"


class FindingSeverity(StrEnum):
    """Severity of a finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingSupportLevel(StrEnum):
    """How much independent evidence supports the finding."""

    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


def _finding_id_validator() -> Callable[[str], str]:
    def _validate(value: str) -> str:
        return validate_id(value, FINDING_ID_PREFIX, "finding_id")

    return _validate


FindingId = Annotated[str, AfterValidator(_finding_id_validator())]


class SecurityFinding(BaseModel):
    """One evidence-grounded conclusion.

    ``evidence_ids`` must reference evidence that exists in the extraction
    result; ``limitations`` records what the rule could *not* establish (for
    example an unknown reputation or an unfinished investigation).
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: FindingId
    incident_id: IncidentId
    finding_type: FindingType
    title: NonEmptyStr
    description: NonEmptyStr
    severity: FindingSeverity
    support_level: FindingSupportLevel
    evidence_ids: EvidenceIdListNonEmpty
    related_indicators: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    rule_id: NonEmptyStr

    @model_validator(mode="after")
    def _validate_uniqueness(self) -> "SecurityFinding":
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence_ids must not contain duplicates")
        return self

    @property
    def is_malicious_grade(self) -> bool:
        """True when the finding is a confirmed malicious indicator match."""
        return self.finding_type is FindingType.MALICIOUS_INDICATOR_MATCH and (
            self.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)
        )

    @property
    def severity_rank(self) -> int:
        """Numeric rank of the severity for deterministic comparisons."""
        return {
            FindingSeverity.LOW: 0,
            FindingSeverity.MEDIUM: 1,
            FindingSeverity.HIGH: 2,
            FindingSeverity.CRITICAL: 3,
        }[self.severity]
