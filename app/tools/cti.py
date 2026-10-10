"""``search_cti``: threat knowledge search across CTI and ATT&CK records."""

from __future__ import annotations

from app.benchmark.loader import BenchmarkLoader
from app.benchmark.schemas import AttackTechniqueRecord, CTIRecord
from app.tools.common import any_text_contains, any_text_exact, apply_limit
from app.tools.contracts import CTISearchInput, CTISearchPayload

TOOL_NAME = "search_cti"


def search_cti(
    request: CTISearchInput, loader: BenchmarkLoader | None = None
) -> CTISearchPayload:
    """Search synthetic CTI records and the ATT&CK technique subset.

    The two collections are filtered, sorted and limited independently and are
    returned separately (``cti_records`` / ``attack_techniques``). Several
    applicable filters combine with AND, and a filter that does not apply to a
    collection is not evaluated for it: an ``indicator`` filter therefore never
    eliminates ATT&CK results. Zero results in either collection is a normal
    outcome.
    """
    dataset = loader or BenchmarkLoader()

    cti_matches = [
        record for record in dataset.load_cti_records() if _matches_cti(record, request)
    ]
    technique_matches = [
        record
        for record in dataset.load_attack_techniques()
        if _matches_technique(record, request)
    ]

    cti_matches.sort(key=lambda record: record.cti_id)
    technique_matches.sort(key=lambda record: record.technique_id)

    cti_records, cti_truncated = apply_limit(cti_matches, request.limit)
    attack_techniques, technique_truncated = apply_limit(technique_matches, request.limit)

    return CTISearchPayload(
        cti_records=cti_records,
        attack_techniques=attack_techniques,
        cti_count=len(cti_records),
        technique_count=len(attack_techniques),
        cti_truncated=cti_truncated,
        technique_truncated=technique_truncated,
    )


def _matches_cti(record: CTIRecord, request: CTISearchInput) -> bool:
    """Indicator membership (exact), technique membership and free-text query."""
    if not any_text_exact(record.indicators, request.indicator):
        return False
    if request.technique_id is not None and request.technique_id not in record.technique_ids:
        return False
    return any_text_contains(
        (record.title, record.summary, *record.malware_families, *record.campaigns),
        request.query,
    )


def _matches_technique(record: AttackTechniqueRecord, request: CTISearchInput) -> bool:
    """Exact technique ID plus free-text query.

    ``indicator`` does not apply to the ATT&CK collection, so it is not
    evaluated here.
    """
    if request.technique_id is not None and record.technique_id != request.technique_id:
        return False
    return any_text_contains(
        (record.name, record.description, *record.tactics, *record.keywords),
        request.query,
    )
