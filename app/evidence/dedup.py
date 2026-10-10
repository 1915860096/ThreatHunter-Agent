"""Stable record identities and source-preserving evidence accumulation.

Identities are built from schema ids (``EPE-``, ``NET-``, ``DNS-``, ``FILE-``,
``CTI-``, ``T…``) and, for records without an id column, from a normalised
content fingerprint. Identities never use free-text descriptions and never use
a bare IP or domain, so unrelated records cannot collapse into one evidence
item.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.benchmark.schemas import AttackTechniqueRecord, CTIRecord, IOCReputationRecord
from app.evidence.contracts import EvidenceSourceReference
from app.evidence.provenance import primary_provenance, sort_references
from app.schemas.evidence import Evidence, EvidenceType

ENDPOINT_RECORD_CLASS = "endpoint_event"
NETWORK_RECORD_CLASS = "network_event"
DNS_RECORD_CLASS = "dns_event"
FILE_RECORD_CLASS = "file_record"
CTI_RECORD_CLASS = "cti_record"
ATTACK_RECORD_CLASS = "attack_technique"
IOC_REPUTATION_RECORD_CLASS = "ioc_reputation"


def telemetry_identity(record_class: str, record_id: str) -> str:
    """Identity of a telemetry or knowledge record that carries an id."""
    return f"{record_class}:{record_id}"


def ioc_reputation_identity(record: IOCReputationRecord) -> str:
    """Normalised content fingerprint of an IOC reputation assertion.

    ``(indicator type, indicator, source, reputation, confidence)`` keeps two
    sources reporting the same indicator apart, and keeps different assertions
    from the same source apart as well.
    """
    return ":".join(
        (
            IOC_REPUTATION_RECORD_CLASS,
            record.indicator_type.value,
            record.indicator.casefold(),
            record.source.casefold(),
            record.reputation.value,
            f"{record.confidence:.4f}",
        )
    )


def cti_record_identity(record: CTIRecord) -> str:
    """Identity of a CTI record."""
    return telemetry_identity(CTI_RECORD_CLASS, record.cti_id)


def attack_technique_identity(record: AttackTechniqueRecord) -> str:
    """Identity of an ATT&CK knowledge record."""
    return telemetry_identity(ATTACK_RECORD_CLASS, record.technique_id)


@dataclass
class _Candidate:
    """One deduplicated evidence item under construction."""

    identity: str
    evidence_type: EvidenceType
    summary: str
    content: dict[str, Any]
    observed_at: datetime | None
    collected_at: datetime
    reliability: float
    tags: list[str] = field(default_factory=list)
    references: list[EvidenceSourceReference] = field(default_factory=list)


class EvidenceAccumulator:
    """Accumulates evidence candidates, deduplicating by stable identity.

    First occurrence wins the content (identical identities carry identical raw
    content); later occurrences are recorded as additional source references,
    so no provenance is lost. Insertion order defines evidence order, which
    keeps repeated extraction runs identical.
    """

    def __init__(self) -> None:
        self._order: list[str] = []
        self._candidates: dict[str, _Candidate] = {}
        self.candidate_count = 0

    def add(
        self,
        *,
        identity: str,
        evidence_type: EvidenceType,
        summary: str,
        content: dict[str, Any],
        observed_at: datetime | None,
        collected_at: datetime,
        reliability: float,
        tags: list[str],
        reference: EvidenceSourceReference,
    ) -> None:
        """Register one raw record occurrence."""
        self.candidate_count += 1
        existing = self._candidates.get(identity)
        if existing is None:
            self._candidates[identity] = _Candidate(
                identity=identity,
                evidence_type=evidence_type,
                summary=summary,
                content=content,
                observed_at=observed_at,
                collected_at=collected_at,
                reliability=reliability,
                tags=list(tags),
                references=[reference],
            )
            self._order.append(identity)
            return

        existing.references.append(reference)
        for tag in tags:
            if tag not in existing.tags:
                existing.tags.append(tag)

    def build(
        self, *, incident_id: str
    ) -> tuple[list[Evidence], dict[str, list[EvidenceSourceReference]]]:
        """Return deduplicated evidence and the multi-source index."""
        evidence: list[Evidence] = []
        sources: dict[str, list[EvidenceSourceReference]] = {}
        for index, identity in enumerate(self._order, start=1):
            candidate = self._candidates[identity]
            evidence_id = f"EV-{index:06d}"
            references = sort_references(candidate.references)
            evidence.append(
                Evidence(
                    evidence_id=evidence_id,
                    incident_id=incident_id,
                    evidence_type=candidate.evidence_type,
                    summary=candidate.summary,
                    content=dict(candidate.content),
                    observed_at=candidate.observed_at,
                    collected_at=candidate.collected_at,
                    reliability=candidate.reliability,
                    provenance=primary_provenance(references),
                    tags=list(candidate.tags),
                )
            )
            sources[evidence_id] = references
        return evidence, sources
