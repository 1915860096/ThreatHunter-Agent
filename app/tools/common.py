"""Shared matching, ordering and truncation helpers for the tool layer.

Matching semantics are frozen:

* IDs and SHA256 values compare exactly;
* IP addresses compare as normalised addresses;
* text fields (host, user, process names, paths, protocol, direction, DNS
  domain, DNS record type, CTI indicators) compare case-insensitively and
  exactly;
* ``command_line_contains``, ``query_contains`` and the CTI / ATT&CK free-text
  query are case-insensitive substring matches;
* time windows are inclusive on both ends;
* distinct filters combine with AND, values inside one list filter combine with
  OR, and a filter that does not apply to a record source is not evaluated for
  that source.

Every predicate treats ``None`` (filter not provided) as "matches everything".
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from typing import Protocol, TypeVar

from app.benchmark.schemas import IOCReputationRecord


class Timestamped(Protocol):
    """Anything that carries the ``timestamp`` used for telemetry ordering."""

    timestamp: datetime


RecordT = TypeVar("RecordT", bound=Timestamped)


def normalize_text(value: str) -> str:
    """Canonical form used for text comparison: trimmed and case-folded."""
    return value.strip().casefold()


def text_exact(candidate: str | None, expected: str | None) -> bool:
    """Case-insensitive exact match."""
    if expected is None:
        return True
    return candidate is not None and normalize_text(candidate) == normalize_text(expected)


def text_contains(candidate: str | None, needle: str | None) -> bool:
    """Case-insensitive substring match."""
    if needle is None:
        return True
    return candidate is not None and normalize_text(needle) in normalize_text(candidate)


def text_in(candidate: str | None, allowed: Sequence[str] | None) -> bool:
    """Case-insensitive exact match against a list of allowed values (OR)."""
    if not allowed:
        return True
    if candidate is None:
        return False
    accepted = {normalize_text(value) for value in allowed}
    return normalize_text(candidate) in accepted


def any_text_exact(candidates: Iterable[str], expected: str | None) -> bool:
    """Case-insensitive exact match against any of a record's own values."""
    if expected is None:
        return True
    return any(text_exact(candidate, expected) for candidate in candidates)


def any_text_contains(candidates: Iterable[str], needle: str | None) -> bool:
    """Case-insensitive substring match across any of a record's own values."""
    if needle is None:
        return True
    return any(text_contains(candidate, needle) for candidate in candidates)


def ip_exact(candidate: str | None, expected: str | None) -> bool:
    """Normalised exact IP comparison (``2001:DB8::1`` equals ``2001:db8::1``)."""
    if expected is None:
        return True
    if candidate is None:
        return False
    try:
        return ipaddress.ip_address(candidate) == ipaddress.ip_address(expected)
    except ValueError:
        return False


def sha256_exact(candidate: str | None, expected: str | None) -> bool:
    """Exact SHA256 comparison."""
    if expected is None:
        return True
    return candidate is not None and candidate == expected


def number_exact(candidate: int, expected: int | None) -> bool:
    """Exact integer comparison (used for ports)."""
    return expected is None or candidate == expected


def time_in_range(
    timestamp: datetime, start_time: datetime | None, end_time: datetime | None
) -> bool:
    """Inclusive time-window check."""
    if start_time is not None and timestamp < start_time:
        return False
    if end_time is not None and timestamp > end_time:
        return False
    return True


def sort_telemetry(records: Iterable[RecordT], id_of: Callable[[RecordT], str]) -> list[RecordT]:
    """Order telemetry by ``timestamp`` ASC, then by record ID ASC."""
    return sorted(records, key=lambda record: (record.timestamp, id_of(record)))


def apply_limit(records: Sequence[RecordT], limit: int) -> tuple[list[RecordT], bool]:
    """Return the first ``limit`` records and whether more were available."""
    return list(records[:limit]), len(records) > limit


def ioc_reputation_sort_key(record: IOCReputationRecord) -> tuple[str, str, str]:
    """Deterministic ordering for IOC reputation records.

    IOC reputation knowledge carries no ID of its own and one indicator may be
    reported by several sources, so ordering uses the stable tuple
    ``(indicator_type, indicator, source)``.
    """
    return (
        record.indicator_type.value,
        record.indicator.casefold(),
        record.source.casefold(),
    )
