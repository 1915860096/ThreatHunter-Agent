"""Shared validation helpers, type aliases and ID conventions.

This module holds the small amount of cross-cutting logic that the domain
schemas share:

* human-readable ID prefixes (``ALT-``, ``EV-``, ...) - prefixes are the only
  ID contract enforced here, because benchmark data uses readable IDs such as
  ``ALT-001`` and ``EV-001`` and not UUIDs;
* timezone handling - every datetime in the domain must be timezone-aware and
  is normalised to UTC;
* bounded scores - ``reliability`` and ``confidence`` are both unit-interval
  values.

Deliberately no base model class and no ID framework: models compose the
aliases below and add their own cross-field ``model_validator``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Annotated

from pydantic import AfterValidator, AwareDatetime, Field


def validate_id(value: str, prefix: str, field_name: str = "id") -> str:
    """Return ``value`` if it is a non-empty string carrying ``prefix``.

    Only the prefix is enforced: ``ALT-001``, ``ALT-2026-09-22-0001`` and
    ``ALT-<uuid>`` are all valid.
    """
    if not value or not value.strip():
        raise ValueError(f"{field_name} must not be empty")
    if not value.startswith(prefix):
        raise ValueError(f"{field_name} must start with '{prefix}'")
    return value


def validate_id_list(
    values: list[str],
    prefix: str,
    field_name: str = "id",
    *,
    min_length: int | None = None,
) -> list[str]:
    """Validate every entry of an ID list and optionally require a minimum size."""
    if min_length is not None and len(values) < min_length:
        raise ValueError(f"{field_name} must contain at least {min_length} item(s)")
    return [validate_id(value, prefix, field_name) for value in values]


def to_utc(value: datetime) -> datetime:
    """Return ``value`` converted to UTC, rejecting naive datetimes."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware (UTC or an explicit offset)")
    return value.astimezone(timezone.utc)


def _non_empty(value: str) -> str:
    if not value or not value.strip():
        raise ValueError("value must not be empty")
    return value


def _prefixed_id(prefix: str, field_name: str) -> Callable[[str], str]:
    def _validate(value: str) -> str:
        return validate_id(value, prefix, field_name)

    return _validate


def _prefixed_id_list(
    prefix: str,
    field_name: str,
    *,
    min_length: int | None = None,
) -> Callable[[list[str]], list[str]]:
    def _validate(values: list[str]) -> list[str]:
        return validate_id_list(values, prefix, field_name, min_length=min_length)

    return _validate


# Reusable field types -------------------------------------------------------

# Required, whitespace-free text (objectives, summaries, rationales, ...).
NonEmptyStr = Annotated[str, AfterValidator(_non_empty)]

# Timezone-aware datetime, normalised to UTC on validation.
UtcDatetime = Annotated[AwareDatetime, AfterValidator(to_utc)]

# Bounded scores. ``Reliability`` describes how trustworthy the observation or
# its source is; ``Confidence`` describes how strongly the evidence supports a
# conclusion. Computing either value is out of scope here.
Reliability = Annotated[float, Field(ge=0.0, le=1.0)]
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]

# ID types.
IncidentId = Annotated[str, AfterValidator(_prefixed_id("INC-", "incident_id"))]
AlertId = Annotated[str, AfterValidator(_prefixed_id("ALT-", "alert_id"))]
PlanId = Annotated[str, AfterValidator(_prefixed_id("PLAN-", "plan_id"))]
StepId = Annotated[str, AfterValidator(_prefixed_id("STEP-", "step_id"))]
ToolCallId = Annotated[str, AfterValidator(_prefixed_id("TC-", "tool_call_id"))]
ToolResultId = Annotated[str, AfterValidator(_prefixed_id("TR-", "tool_result_id"))]
EvidenceId = Annotated[str, AfterValidator(_prefixed_id("EV-", "evidence_id"))]
FindingId = Annotated[str, AfterValidator(_prefixed_id("IOCF-", "finding_id"))]
ReportId = Annotated[str, AfterValidator(_prefixed_id("RPT-", "report_id"))]

# ID list types.
ToolCallIdList = Annotated[list[str], AfterValidator(_prefixed_id_list("TC-", "tool_call_ids"))]
EvidenceIdList = Annotated[list[str], AfterValidator(_prefixed_id_list("EV-", "evidence_ids"))]
EvidenceIdListNonEmpty = Annotated[
    list[str],
    AfterValidator(_prefixed_id_list("EV-", "evidence_ids", min_length=1)),
]
