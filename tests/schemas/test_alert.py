"""Tests for the ``SecurityAlert`` contract."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas import AlertSeverity, SecurityAlert


def alert_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "alert_id": "ALT-001",
        "timestamp": "2026-09-22T10:00:00Z",
        "source": "edr",
        "severity": "high",
        "event_type": "process_creation",
        "host": "ws-042",
        "user": "alice",
        "src_ip": "10.0.0.5",
        "dst_ip": "203.0.113.10",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand ZQBjAGgAbwA=",
        "raw": {"vendor_event_id": 4688},
    }
    payload.update(overrides)
    return payload


def test_valid_alert_is_accepted() -> None:
    alert = SecurityAlert(**alert_payload())

    assert alert.alert_id == "ALT-001"
    assert alert.severity is AlertSeverity.HIGH
    assert alert.source == "edr"
    assert alert.event_type == "process_creation"
    assert alert.raw == {"vendor_event_id": 4688}


def test_optional_context_fields_default_to_none() -> None:
    alert = SecurityAlert(
        alert_id="ALT-002",
        timestamp="2026-09-22T10:00:00Z",
        source="siem",
        severity="low",
        event_type="login_failure",
    )

    assert alert.host is None
    assert alert.user is None
    assert alert.src_ip is None
    assert alert.dst_ip is None
    assert alert.process_name is None
    assert alert.command_line is None
    assert alert.raw == {}


def test_raw_default_is_not_shared_between_instances() -> None:
    payload = alert_payload()
    payload.pop("raw")

    first = SecurityAlert(**payload)
    second = SecurityAlert(**payload)

    first.raw["added"] = True

    assert second.raw == {}


@pytest.mark.parametrize("alert_id", ["EV-001", "alt-001", "ALT001", "001", ""])
def test_invalid_alert_id_prefix_is_rejected(alert_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        SecurityAlert(**alert_payload(alert_id=alert_id))

    assert exc_info.value.errors()[0]["loc"] == ("alert_id",)


def test_naive_timestamp_object_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        SecurityAlert(**alert_payload(timestamp=datetime(2026, 9, 22, 10, 0)))

    assert exc_info.value.errors()[0]["loc"] == ("timestamp",)


def test_timestamp_string_without_offset_is_rejected() -> None:
    with pytest.raises(ValidationError):
        SecurityAlert(**alert_payload(timestamp="2026-09-22T10:00:00"))


def test_timezone_aware_timestamp_is_normalised_to_utc() -> None:
    alert = SecurityAlert(**alert_payload(timestamp="2026-09-22T18:00:00+08:00"))

    assert alert.timestamp == datetime(2026, 9, 22, 10, 0, tzinfo=timezone.utc)
    assert alert.timestamp.tzinfo is timezone.utc


def test_timestamp_serialises_as_iso8601_utc() -> None:
    alert = SecurityAlert(
        **alert_payload(timestamp=datetime(2026, 9, 22, 12, 0, tzinfo=timezone(timedelta(hours=2))))
    )

    assert json.loads(alert.model_dump_json())["timestamp"] == "2026-09-22T10:00:00Z"


@pytest.mark.parametrize("field", ["source", "event_type"])
@pytest.mark.parametrize("value", ["", "   "])
def test_empty_source_or_event_type_is_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        SecurityAlert(**alert_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_unknown_severity_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        SecurityAlert(**alert_payload(severity="urgent"))

    assert exc_info.value.errors()[0]["loc"] == ("severity",)


def test_severity_serialises_to_its_lowercase_value() -> None:
    alert = SecurityAlert(**alert_payload(severity=AlertSeverity.CRITICAL))

    assert json.loads(alert.model_dump_json())["severity"] == "critical"
