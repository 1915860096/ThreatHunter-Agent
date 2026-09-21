"""Findings: investigation conclusions backed by evidence."""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import (
    Confidence,
    EvidenceIdListNonEmpty,
    FindingId,
    IncidentId,
    NonEmptyStr,
)

# MITRE ATT&CK technique IDs: "T1059" or a sub-technique such as "T1059.001".
MITRE_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class IOCType(StrEnum):
    """Supported indicator types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IOCReputation(StrEnum):
    """Reputation assigned to an indicator."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class IOCFinding(BaseModel):
    """An indicator conclusion, where ``confidence`` is the support strength of
    the referenced evidence rather than a reputation score."""

    finding_id: FindingId
    incident_id: IncidentId
    indicator: NonEmptyStr
    indicator_type: IOCType
    reputation: IOCReputation
    confidence: Confidence
    evidence_ids: EvidenceIdListNonEmpty
    tags: list[str] = Field(default_factory=list)


class AttackTechniqueFinding(BaseModel):
    """A suspected MITRE ATT&CK technique. Supporting value object: it is owned
    by its report, so it carries no top-level ID of its own."""

    technique_id: str
    technique_name: NonEmptyStr
    confidence: Confidence
    evidence_ids: EvidenceIdListNonEmpty

    @field_validator("technique_id")
    @classmethod
    def _validate_technique_id(cls, value: str) -> str:
        if not MITRE_TECHNIQUE_ID_PATTERN.fullmatch(value):
            raise ValueError(
                "technique_id must be a MITRE ATT&CK ID such as 'T1059' or 'T1059.001'"
            )
        return value
