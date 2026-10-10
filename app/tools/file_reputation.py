"""``lookup_file_reputation``: file telemetry followed by SHA256 enrichment."""

from __future__ import annotations

from app.benchmark.loader import BenchmarkLoader
from app.benchmark.schemas import FileRecord, IOCReputationRecord
from app.schemas.findings import IOCType
from app.tools.common import (
    ioc_reputation_sort_key,
    sha256_exact,
    sort_telemetry,
    text_exact,
)
from app.tools.contracts import FileReputationInput, FileReputationPayload

TOOL_NAME = "lookup_file_reputation"


def lookup_file_reputation(
    request: FileReputationInput, loader: BenchmarkLoader | None = None
) -> FileReputationPayload:
    """Return matching file telemetry and the reputation of its SHA256 values.

    Stage 1 queries the case file telemetry; stage 2 enriches the matched files
    with ``sha256`` reputation records from shared knowledge. Reputation is
    reported separately - it is never merged into the file records, no
    ``IOCFinding`` is created and no confidence is computed. Records whose
    reputation is ``unknown`` are kept; zero matches is a successful empty
    result.
    """
    dataset = loader or BenchmarkLoader()
    records = dataset.load_file_records(request.case_id)

    matched = [record for record in records if _matches(record, request)]
    files = sort_telemetry(matched, id_of=lambda record: record.file_id)

    hashes = {record.sha256 for record in files if record.sha256 is not None}
    reputations: list[IOCReputationRecord] = []
    if hashes:
        reputations = [
            record
            for record in dataset.load_ioc_reputation_records()
            if record.indicator_type is IOCType.SHA256 and record.indicator in hashes
        ]
        reputations.sort(key=ioc_reputation_sort_key)

    return FileReputationPayload(
        case_id=request.case_id,
        files=files,
        reputations=reputations,
        count=len(files),
    )


def _matches(record: FileRecord, request: FileReputationInput) -> bool:
    """Core filters (AND) with ``host`` as an additional narrowing filter."""
    return (
        sha256_exact(record.sha256, request.sha256)
        and text_exact(record.path, request.path)
        and text_exact(record.file_name, request.file_name)
        and text_exact(record.host, request.host)
    )
