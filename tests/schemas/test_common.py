"""Tests for the shared ID and datetime helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.schemas.common import to_utc, validate_id, validate_id_list


def test_validate_id_accepts_prefixed_id() -> None:
    assert validate_id("ALT-001", "ALT-", "alert_id") == "ALT-001"


def test_validate_id_accepts_non_uuid_suffix() -> None:
    assert validate_id("EV-2026-09-22-0001", "EV-", "evidence_id") == "EV-2026-09-22-0001"


@pytest.mark.parametrize("value", ["EV-001", "ALT001", "alt-001", "A-001", "ALT_001"])
def test_validate_id_rejects_other_prefixes(value: str) -> None:
    with pytest.raises(ValueError, match="must start with 'ALT-'"):
        validate_id(value, "ALT-", "alert_id")


def test_validate_id_only_enforces_the_prefix() -> None:
    # Only the prefix is contractual: readable IDs such as "ALT-001" and
    # "ALT-2026-09-22-0001" are both allowed, and no UUID shape is required.
    assert validate_id("ALT-", "ALT-", "alert_id") == "ALT-"
    assert validate_id("ALT-2026-09-22-0001", "ALT-", "alert_id") == "ALT-2026-09-22-0001"


def test_validate_id_rejects_empty_and_whitespace() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        validate_id("", "ALT-", "alert_id")

    with pytest.raises(ValueError, match="must not be empty"):
        validate_id("   ", "ALT-", "alert_id")


def test_validate_id_list_checks_every_entry() -> None:
    assert validate_id_list(["EV-001", "EV-002"], "EV-", "evidence_ids") == [
        "EV-001",
        "EV-002",
    ]

    with pytest.raises(ValueError, match="must start with 'EV-'"):
        validate_id_list(["EV-001", "TC-002"], "EV-", "evidence_ids")


def test_validate_id_list_can_require_a_minimum_length() -> None:
    assert validate_id_list(["EV-001"], "EV-", "evidence_ids", min_length=1) == ["EV-001"]

    with pytest.raises(ValueError, match="must contain at least 1 item"):
        validate_id_list([], "EV-", "evidence_ids", min_length=1)


def test_to_utc_converts_offset_to_utc() -> None:
    aware = datetime(2026, 9, 22, 18, 0, tzinfo=timezone(timedelta(hours=8)))

    converted = to_utc(aware)

    assert converted == datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
    assert converted.tzinfo is timezone.utc


def test_to_utc_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        to_utc(datetime(2026, 9, 22, 10, 0))
