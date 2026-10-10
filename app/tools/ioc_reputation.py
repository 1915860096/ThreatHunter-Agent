"""``lookup_ioc_reputation``: exact indicator lookup in shared knowledge."""

from __future__ import annotations

from app.benchmark.loader import BenchmarkLoader
from app.tools.common import ioc_reputation_sort_key, text_exact
from app.tools.contracts import IOCReputationInput, IOCReputationPayload

TOOL_NAME = "lookup_ioc_reputation"


def lookup_ioc_reputation(
    request: IOCReputationInput, loader: BenchmarkLoader | None = None
) -> IOCReputationPayload:
    """Return every reputation record known for ``request.indicator``.

    Matching is exact (case-folded for text indicators) - never substring or
    fuzzy. One indicator may be reported by several sources, so all matching
    records are returned in deterministic order.

    ``found`` distinguishes a known indicator from an absent one: a known
    indicator with reputation ``unknown`` returns ``found=True`` with records,
    while an indicator missing from the knowledge base returns ``found=False``
    with no records. The tool never infers a reputation of its own.
    """
    dataset = loader or BenchmarkLoader()

    matches = [
        record
        for record in dataset.load_ioc_reputation_records()
        if text_exact(record.indicator, request.indicator)
        and (request.ioc_type is None or record.indicator_type is request.ioc_type)
    ]
    matches.sort(key=ioc_reputation_sort_key)

    return IOCReputationPayload(
        indicator=request.indicator,
        ioc_type=request.ioc_type,
        found=bool(matches),
        records=matches,
    )
