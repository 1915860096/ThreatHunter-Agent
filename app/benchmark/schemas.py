"""Pydantic v2 contracts for benchmark dataset artifacts.

Everything in this module describes *dataset* content:

* telemetry records (``EndpointEvent``, ``NetworkEvent``, ``DNSEvent``,
  ``FileRecord``) - synthetic security telemetry, not tool output;
* shared knowledge (``IOCReputationRecord``, ``CTIRecord``,
  ``AttackTechniqueRecord``);
* case metadata and ground truth (``CaseMetadata``, ``CaseGroundTruth``).

Telemetry is deliberately *not* modelled as ``ToolResult``, ``Evidence`` or
``Finding``: those T02 runtime contracts describe what tools and the agent
produce later. Telemetry IDs follow the ``EPE-<case>-<n>``, ``NET-``, ``DNS-``
and ``FILE-`` scheme so a future ``EvidenceProvenance.raw_ref`` can point at
``CASE-001/telemetry/endpoint_events.json#EPE-001-003``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Annotated, Any, Final, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from app.schemas.common import Confidence, NonEmptyStr, UtcDatetime, validate_id
from app.schemas.findings import IOCReputation, IOCType, MITRE_TECHNIQUE_ID_PATTERN
from app.schemas.report import InvestigationVerdict

# ID prefixes owned by the dataset layer. They are case-scoped and unrelated to
# the T02 runtime ID contract (INC-, ALT-, EV-, ...).
ENDPOINT_EVENT_PREFIX: Final[str] = "EPE-"
NETWORK_EVENT_PREFIX: Final[str] = "NET-"
DNS_EVENT_PREFIX: Final[str] = "DNS-"
FILE_PREFIX: Final[str] = "FILE-"
CTI_PREFIX: Final[str] = "CTI-"
TELEMETRY_ID_PREFIXES: Final[tuple[str, ...]] = (
    ENDPOINT_EVENT_PREFIX,
    NETWORK_EVENT_PREFIX,
    DNS_EVENT_PREFIX,
    FILE_PREFIX,
)

TELEMETRY_SOURCE_NAMES: Final[tuple[str, ...]] = ("endpoint", "network", "dns", "files")
EXPECTED_SOURCE_NAMES: Final[tuple[str, ...]] = (*TELEMETRY_SOURCE_NAMES, "ioc", "cti", "attack")

# Answers must never live in agent-visible case metadata.
GROUND_TRUTH_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "verdict",
        "expected_verdict",
        "expected_iocs",
        "expected_techniques",
        "key_evidence",
        "acceptable_evidence",
        "expected_investigation",
    }
)

SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

SourceName = Literal["endpoint", "network", "dns", "files"]
ExpectedSourceName = Literal["endpoint", "network", "dns", "files", "ioc", "cti", "attack"]


def _prefixed_id(prefix: str, field_name: str) -> Callable[[str], str]:
    def _validate(value: str) -> str:
        return validate_id(value, prefix, field_name)

    return _validate


def _telemetry_id(value: str) -> str:
    if not value or not value.strip():
        raise ValueError("telemetry ID must not be empty")
    if not value.startswith(TELEMETRY_ID_PREFIXES):
        allowed = ", ".join(f"'{prefix}'" for prefix in TELEMETRY_ID_PREFIXES)
        raise ValueError(f"telemetry ID must start with one of {allowed}")
    return value


def _telemetry_id_list(values: list[str]) -> list[str]:
    return [_telemetry_id(value) for value in values]


def _validate_sha256(value: str) -> str:
    if not SHA256_PATTERN.fullmatch(value):
        raise ValueError("sha256 must be a 64-character lowercase hexadecimal digest")
    return value


def _validate_ip_address(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{value!r} is not a valid IP address") from exc
    return value


def _validate_mitre_technique_id(value: str) -> str:
    if not MITRE_TECHNIQUE_ID_PATTERN.fullmatch(value):
        raise ValueError(
            "technique_id must be a MITRE ATT&CK ID such as 'T1059' or 'T1059.001'"
        )
    return value


# Reusable dataset field types ----------------------------------------------

CaseId = Annotated[str, AfterValidator(_prefixed_id("CASE-", "case_id"))]
InitialAlertId = Annotated[str, AfterValidator(_prefixed_id("ALT-", "initial_alert_id"))]
EndpointEventId = Annotated[str, AfterValidator(_prefixed_id("EPE-", "event_id"))]
NetworkEventId = Annotated[str, AfterValidator(_prefixed_id("NET-", "event_id"))]
DNSEventId = Annotated[str, AfterValidator(_prefixed_id("DNS-", "event_id"))]
FileId = Annotated[str, AfterValidator(_prefixed_id("FILE-", "file_id"))]
CtiId = Annotated[str, AfterValidator(_prefixed_id("CTI-", "cti_id"))]
TelemetryId = Annotated[str, AfterValidator(_telemetry_id)]
TelemetryIdList = Annotated[list[str], AfterValidator(_telemetry_id_list)]
Sha256 = Annotated[str, AfterValidator(_validate_sha256)]
IpAddress = Annotated[str, AfterValidator(_validate_ip_address)]
PortNumber = Annotated[int, Field(ge=1, le=65535)]
ByteCount = Annotated[int, Field(ge=0)]
MitreTechniqueId = Annotated[str, AfterValidator(_validate_mitre_technique_id)]


class CaseMetadata(BaseModel):
    """Agent-visible description of one benchmark case.

    Case metadata must stay answer-free: verdicts, expected IOCs/techniques and
    key evidence belong to ``datasets/ground_truth`` and are only readable via
    :class:`~app.benchmark.loader.GroundTruthLoader`.
    """

    model_config = ConfigDict(extra="forbid")

    case_id: CaseId
    name: NonEmptyStr
    description: NonEmptyStr
    difficulty: NonEmptyStr
    available_sources: list[SourceName] = Field(min_length=1)
    initial_alert_id: InitialAlertId

    @model_validator(mode="before")
    @classmethod
    def _reject_ground_truth_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            leaked = sorted(GROUND_TRUTH_FIELD_NAMES.intersection(data))
            if leaked:
                raise ValueError(
                    f"case metadata must not contain ground truth fields: {leaked}"
                )
        return data


class EndpointEvent(BaseModel):
    """Synthetic endpoint telemetry (process, file and authentication activity).

    ``event_type`` uses telemetry vocabulary such as ``process_creation``,
    ``file_creation``, ``authentication_failed`` or ``authentication_success``.
    """

    event_id: EndpointEventId
    timestamp: UtcDatetime
    host: NonEmptyStr
    user: str | None = None
    event_type: NonEmptyStr
    process_name: str | None = None
    pid: int | None = Field(default=None, gt=0)
    parent_process_name: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    sha256: Sha256 | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class NetworkEvent(BaseModel):
    """Synthetic network telemetry (flow-style records)."""

    event_id: NetworkEventId
    timestamp: UtcDatetime
    src_host: str | None = None
    src_ip: IpAddress
    src_port: PortNumber | None = None
    dst_ip: IpAddress
    dst_port: PortNumber
    protocol: NonEmptyStr
    direction: NonEmptyStr
    bytes_sent: ByteCount | None = None
    bytes_received: ByteCount | None = None
    process_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DNSEvent(BaseModel):
    """Synthetic DNS telemetry."""

    event_id: DNSEventId
    timestamp: UtcDatetime
    host: NonEmptyStr
    src_ip: IpAddress
    query: NonEmptyStr
    record_type: NonEmptyStr
    response: str | None = None
    process_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FileRecord(BaseModel):
    """Synthetic file telemetry for files observed on an endpoint."""

    file_id: FileId
    timestamp: UtcDatetime
    host: NonEmptyStr
    path: NonEmptyStr
    file_name: NonEmptyStr
    sha256: Sha256 | None = None
    size: int | None = Field(default=None, ge=0)
    signed: bool | None = None
    signer: str | None = None
    source_url: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IOCReputationRecord(BaseModel):
    """Shared IOC reputation knowledge used to enrich investigation evidence."""

    indicator: NonEmptyStr
    indicator_type: IOCType
    reputation: IOCReputation
    confidence: Confidence
    source: NonEmptyStr
    tags: list[str] = Field(default_factory=list)
    last_seen: UtcDatetime | None = None


class CTIRecord(BaseModel):
    """Synthetic cyber threat intelligence record (source: ``benchmark-ti``)."""

    cti_id: CtiId
    title: NonEmptyStr
    summary: NonEmptyStr
    indicators: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    technique_ids: list[MitreTechniqueId] = Field(default_factory=list)
    source: NonEmptyStr
    published_at: UtcDatetime


class AttackTechniqueRecord(BaseModel):
    """The ATT&CK know-how subset this benchmark needs."""

    technique_id: MitreTechniqueId
    name: NonEmptyStr
    description: NonEmptyStr
    tactics: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)


class GroundTruthIOC(BaseModel):
    """An indicator an evaluation run is expected to surface."""

    indicator: NonEmptyStr
    indicator_type: IOCType
    reputation: IOCReputation


class GroundTruthTechnique(BaseModel):
    """An ATT&CK technique an evaluation run is expected to surface."""

    technique_id: MitreTechniqueId
    required: bool = True


class ExpectedInvestigation(BaseModel):
    """Which sources an investigation is expected to consult.

    Deliberately source-level only: the benchmark never prescribes a tool call
    order.
    """

    required_source_types: list[ExpectedSourceName] = Field(default_factory=list)
    optional_source_types: list[ExpectedSourceName] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_source_types(self) -> "ExpectedInvestigation":
        for field_name, values in (
            ("required_source_types", self.required_source_types),
            ("optional_source_types", self.optional_source_types),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must not contain duplicates")

        overlap = sorted(set(self.required_source_types) & set(self.optional_source_types))
        if overlap:
            raise ValueError(
                f"source types must not be both required and optional: {overlap}"
            )
        return self


class CaseGroundTruth(BaseModel):
    """Evaluation-only answers for one case.

    A case does not have to declare IOCs or techniques: benign and inconclusive
    cases legitimately have none.
    """

    case_id: CaseId
    expected_verdict: InvestigationVerdict
    expected_iocs: list[GroundTruthIOC] = Field(default_factory=list)
    expected_techniques: list[GroundTruthTechnique] = Field(default_factory=list)
    key_evidence: TelemetryIdList = Field(default_factory=list)
    acceptable_evidence: TelemetryIdList = Field(default_factory=list)
    expected_investigation: ExpectedInvestigation
    notes: str | None = None

    @model_validator(mode="after")
    def _validate_evidence_sets(self) -> "CaseGroundTruth":
        if len(self.key_evidence) != len(set(self.key_evidence)):
            raise ValueError("key_evidence must not contain duplicate IDs")

        overlap = sorted(set(self.key_evidence) & set(self.acceptable_evidence))
        if overlap:
            raise ValueError(
                f"key_evidence and acceptable_evidence must not overlap: {overlap}"
            )
        return self
