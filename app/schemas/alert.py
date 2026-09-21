"""Security alert contract: the raw input of an investigation."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.common import AlertId, NonEmptyStr, UtcDatetime


class AlertSeverity(StrEnum):
    """Severity assigned to an alert by the producing security control."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAlert(BaseModel):
    """A security alert that triggers an investigation.

    Alert fields are already parsed by the upstream control; ``raw`` keeps the
    untouched event so later stages can always fall back to the original
    payload.
    """

    alert_id: AlertId
    timestamp: UtcDatetime
    source: NonEmptyStr
    severity: AlertSeverity
    event_type: NonEmptyStr
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
