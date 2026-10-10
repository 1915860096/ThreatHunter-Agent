"""Raw-record locators and provenance mapping for T06 evidence.

Locator convention (aligned with the T03 ``raw_ref`` convention documented in
``app/benchmark/schemas.py``):

* case telemetry - ``CASE-001/telemetry/endpoint_events.json#EPE-001-003``
* shared knowledge - ``knowledge/cti_records.json#CTI-001``

Knowledge records without an id column use a stable composite key, for example
``knowledge/ioc_reputation.json#203.0.113.47|benchmark-ti``.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.benchmark.loader import (
    ATTACK_TECHNIQUES_FILE,
    CTI_RECORDS_FILE,
    DNS_EVENTS_FILE,
    ENDPOINT_EVENTS_FILE,
    FILES_FILE,
    IOC_REPUTATION_FILE,
    NETWORK_EVENTS_FILE,
)
from app.evidence.contracts import EvidenceSourceReference
from app.schemas.evidence import EvidenceProvenance

TELEMETRY_DIRECTORY = "telemetry"
KNOWLEDGE_DIRECTORY = "knowledge"


def case_telemetry_raw_ref(case_id: str, file_name: str, record_id: str) -> str:
    """Return ``CASE-001/telemetry/<file>#<record id>``."""
    return f"{case_id}/{TELEMETRY_DIRECTORY}/{file_name}#{record_id}"


def knowledge_raw_ref(file_name: str, key: str) -> str:
    """Return ``knowledge/<file>#<stable key>``."""
    return f"{KNOWLEDGE_DIRECTORY}/{file_name}#{key}"


def endpoint_raw_ref(case_id: str, record_id: str) -> str:
    return case_telemetry_raw_ref(case_id, ENDPOINT_EVENTS_FILE, record_id)


def network_raw_ref(case_id: str, record_id: str) -> str:
    return case_telemetry_raw_ref(case_id, NETWORK_EVENTS_FILE, record_id)


def dns_raw_ref(case_id: str, record_id: str) -> str:
    return case_telemetry_raw_ref(case_id, DNS_EVENTS_FILE, record_id)


def file_raw_ref(case_id: str, record_id: str) -> str:
    return case_telemetry_raw_ref(case_id, FILES_FILE, record_id)


def ioc_reputation_raw_ref(indicator: str, source: str) -> str:
    return knowledge_raw_ref(IOC_REPUTATION_FILE, f"{indicator}|{source}")


def cti_raw_ref(cti_id: str) -> str:
    return knowledge_raw_ref(CTI_RECORDS_FILE, cti_id)


def attack_technique_raw_ref(technique_id: str) -> str:
    return knowledge_raw_ref(ATTACK_TECHNIQUES_FILE, technique_id)


def reference_sort_key(reference: EvidenceSourceReference) -> tuple[str, str, str, str]:
    """Stable ordering key - never depends on hash randomness."""
    return (
        reference.tool_result_id,
        reference.tool_call_id,
        reference.record_id,
        reference.raw_ref,
    )


def sort_references(
    references: Iterable[EvidenceSourceReference],
) -> list[EvidenceSourceReference]:
    """Return references in deterministic order."""
    return sorted(references, key=reference_sort_key)


def primary_provenance(references: list[EvidenceSourceReference]) -> EvidenceProvenance:
    """Map the first (stable) source reference onto the frozen T02 provenance.

    T02 ``EvidenceProvenance`` can describe one source; the complete list stays
    in :class:`~app.evidence.contracts.EvidenceExtractionResult`.
    """
    primary = sort_references(references)[0]
    return EvidenceProvenance(
        source_type=primary.source_type,
        source_name=primary.source_name,
        tool_call_id=primary.tool_call_id,
        tool_result_id=primary.tool_result_id,
        raw_ref=primary.raw_ref,
    )
