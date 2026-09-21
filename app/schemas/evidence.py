"""Evidence contracts: normalised facts plus where they came from."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas.common import (
    EvidenceId,
    IncidentId,
    NonEmptyStr,
    Reliability,
    ToolCallId,
    ToolResultId,
    UtcDatetime,
)


class EvidenceType(StrEnum):
    """Category of the observed activity an evidence item describes."""

    PROCESS_EXECUTION = "process_execution"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"
    FILE_ACTIVITY = "file_activity"
    AUTHENTICATION = "authentication"
    IOC_REPUTATION = "ioc_reputation"
    THREAT_INTELLIGENCE = "threat_intelligence"
    ATTACK_KNOWLEDGE = "attack_knowledge"
    OTHER = "other"


class EvidenceSourceType(StrEnum):
    """Kind of source an evidence item was derived from."""

    ALERT = "alert"
    TOOL = "tool"
    KNOWLEDGE = "knowledge"
    ANALYST = "analyst"


class EvidenceProvenance(BaseModel):
    """Where an evidence item came from, including its raw-data pointer."""

    source_type: EvidenceSourceType
    source_name: NonEmptyStr
    tool_call_id: ToolCallId | None = None
    tool_result_id: ToolResultId | None = None
    raw_ref: str | None = None

    @model_validator(mode="after")
    def _validate_tool_references(self) -> "EvidenceProvenance":
        if self.source_type is EvidenceSourceType.TOOL and (
            self.tool_call_id is None or self.tool_result_id is None
        ):
            raise ValueError(
                "tool_call_id and tool_result_id are required when source_type is 'tool'"
            )
        return self


class Evidence(BaseModel):
    """A normalised fact that investigation reasoning can rely on.

    Evidence is distilled from a :class:`~app.schemas.tools.ToolResult`, an
    alert, or knowledge - it never duplicates the raw tool output. ``content``
    holds the normalised facts, ``provenance.raw_ref`` points at the original
    record, and ``reliability`` expresses how trustworthy the source and the
    observation itself are.
    """

    evidence_id: EvidenceId
    incident_id: IncidentId
    evidence_type: EvidenceType
    summary: NonEmptyStr
    content: dict[str, Any]
    observed_at: UtcDatetime | None = None
    collected_at: UtcDatetime
    reliability: Reliability
    provenance: EvidenceProvenance
    tags: list[str] = Field(default_factory=list)

    @field_validator("content")
    @classmethod
    def _validate_content(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not value:
            raise ValueError("content must not be empty")
        return value
