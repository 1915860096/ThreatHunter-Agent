"""Input and payload contracts for the T04 investigation tools.

Input schemas describe what a caller may ask for; payload schemas describe the
raw structured answer a tool returns. Payloads embed the *existing* T03
telemetry and knowledge models (``EndpointEvent``, ``NetworkEvent``,
``DNSEvent``, ``FileRecord``, ``IOCReputationRecord``, ``CTIRecord``,
``AttackTechniqueRecord``) - the tool layer defines no duplicate telemetry
models.

A payload is never ``Evidence``: it is the unprocessed tool answer, which a
later stage may distil into provenance-carrying evidence.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from app.benchmark.schemas import (
    AttackTechniqueRecord,
    CaseId,
    CTIRecord,
    DNSEvent,
    EndpointEvent,
    FileRecord,
    IOCReputationRecord,
    IpAddress,
    MitreTechniqueId,
    NetworkEvent,
    PortNumber,
    Sha256,
)
from app.schemas.common import NonEmptyStr, UtcDatetime
from app.schemas.findings import IOCType

DEFAULT_ENDPOINT_LIMIT = 100
DEFAULT_NETWORK_LIMIT = 100
DEFAULT_CTI_LIMIT = 20

MAX_TELEMETRY_LIMIT = 500
MAX_CTI_LIMIT = 100


def _validate_time_window(start_time: datetime | None, end_time: datetime | None) -> None:
    """Reject an inverted time window; both ends are inclusive."""
    if start_time is not None and end_time is not None and start_time > end_time:
        raise ValueError("start_time must not be later than end_time")


class EndpointSearchInput(BaseModel):
    """Filters for endpoint telemetry of one case.

    Every provided filter combines with AND; the values inside ``event_types``
    combine with OR. A missing filter matches everything.
    """

    case_id: CaseId
    event_types: list[str] | None = None
    host: str | None = None
    user: str | None = None
    process_name: str | None = None
    parent_process_name: str | None = None
    command_line_contains: str | None = None
    file_path: str | None = None
    sha256: Sha256 | None = None
    start_time: UtcDatetime | None = None
    end_time: UtcDatetime | None = None
    limit: int = Field(default=DEFAULT_ENDPOINT_LIMIT, ge=1, le=MAX_TELEMETRY_LIMIT)

    @model_validator(mode="after")
    def _validate_window(self) -> "EndpointSearchInput":
        _validate_time_window(self.start_time, self.end_time)
        return self


class NetworkSearchInput(BaseModel):
    """Filters for network and DNS telemetry of one case.

    ``host``, ``src_ip``, ``process_name`` and the time window apply to both
    network and DNS records. ``dst_ip``, ``dst_port``, ``protocol`` and
    ``direction`` only apply to network records; ``domain``, ``query_contains``
    and ``record_type`` only apply to DNS records. A filter that does not apply
    to a source is simply not evaluated for that source.
    """

    case_id: CaseId
    host: str | None = None
    src_ip: IpAddress | None = None
    dst_ip: IpAddress | None = None
    dst_port: PortNumber | None = None
    protocol: str | None = None
    direction: str | None = None
    domain: str | None = None
    query_contains: str | None = None
    record_type: str | None = None
    process_name: str | None = None
    start_time: UtcDatetime | None = None
    end_time: UtcDatetime | None = None
    include_network: bool = True
    include_dns: bool = True
    limit: int = Field(default=DEFAULT_NETWORK_LIMIT, ge=1, le=MAX_TELEMETRY_LIMIT)

    @model_validator(mode="after")
    def _validate_request(self) -> "NetworkSearchInput":
        _validate_time_window(self.start_time, self.end_time)
        if not self.include_network and not self.include_dns:
            raise ValueError("at least one of include_network or include_dns must be True")
        return self


class FileReputationInput(BaseModel):
    """Filters for file telemetry of one case plus SHA256 reputation enrichment.

    At least one core query field (``sha256``, ``path``, ``file_name``) is
    required; ``host`` only narrows an existing query.
    """

    case_id: CaseId
    sha256: Sha256 | None = None
    path: str | None = None
    file_name: str | None = None
    host: str | None = None

    @model_validator(mode="after")
    def _require_core_query_field(self) -> "FileReputationInput":
        if self.sha256 is None and self.path is None and self.file_name is None:
            raise ValueError("at least one of sha256, path or file_name is required")
        return self


class IOCReputationInput(BaseModel):
    """Exact indicator lookup in the shared IOC reputation knowledge."""

    indicator: NonEmptyStr
    ioc_type: IOCType | None = None


class CTISearchInput(BaseModel):
    """Free-text / indicator / technique search across threat knowledge.

    At least one of ``query``, ``indicator`` or ``technique_id`` is required.
    ``query`` and ``indicator`` must not be blank when provided.
    """

    query: str | None = None
    indicator: str | None = None
    technique_id: MitreTechniqueId | None = None
    limit: int = Field(default=DEFAULT_CTI_LIMIT, ge=1, le=MAX_CTI_LIMIT)

    @model_validator(mode="after")
    def _validate_request(self) -> "CTISearchInput":
        for field_name, value in (("query", self.query), ("indicator", self.indicator)):
            if value is not None and not value.strip():
                raise ValueError(f"{field_name} must not be empty or whitespace")

        if self.query is None and self.indicator is None and self.technique_id is None:
            raise ValueError("at least one of query, indicator or technique_id is required")
        return self


class EndpointSearchPayload(BaseModel):
    """Matching endpoint events, ordered by timestamp then ``event_id``."""

    case_id: CaseId
    items: list[EndpointEvent] = Field(default_factory=list)
    count: int = Field(ge=0)
    truncated: bool = False


class NetworkSearchPayload(BaseModel):
    """Matching network and DNS records, limited per source and ordered each."""

    case_id: CaseId
    network_events: list[NetworkEvent] = Field(default_factory=list)
    dns_events: list[DNSEvent] = Field(default_factory=list)
    network_count: int = Field(ge=0)
    dns_count: int = Field(ge=0)
    network_truncated: bool = False
    dns_truncated: bool = False


class FileReputationPayload(BaseModel):
    """File telemetry matches plus the SHA256 reputation records backing them.

    ``count`` is the number of returned ``FileRecord`` items. Reputation is
    enrichment only: it is never merged into the file records, and an
    ``unknown`` reputation is kept as-is.
    """

    case_id: CaseId
    files: list[FileRecord] = Field(default_factory=list)
    reputations: list[IOCReputationRecord] = Field(default_factory=list)
    count: int = Field(ge=0)


class IOCReputationPayload(BaseModel):
    """Reputation records for one indicator.

    ``found`` describes whether the knowledge base knows the indicator at all;
    an ``unknown`` reputation is a known indicator, ``found=False`` is an
    absent one.
    """

    indicator: str
    ioc_type: IOCType | None = None
    found: bool
    records: list[IOCReputationRecord] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_found_consistency(self) -> "IOCReputationPayload":
        if self.found and not self.records:
            raise ValueError("records must not be empty when found is True")
        if not self.found and self.records:
            raise ValueError("records must be empty when found is False")
        return self


class CTISearchPayload(BaseModel):
    """Threat knowledge results, kept separate per collection."""

    cti_records: list[CTIRecord] = Field(default_factory=list)
    attack_techniques: list[AttackTechniqueRecord] = Field(default_factory=list)
    cti_count: int = Field(ge=0)
    technique_count: int = Field(ge=0)
    cti_truncated: bool = False
    technique_truncated: bool = False
