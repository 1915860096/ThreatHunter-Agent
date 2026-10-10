"""Deterministic evidence extraction from a T05 investigation run.

Design rules:

* only **successful** tool results are read; a failed tool result carries no
  fact and produces no evidence (it is reported as an information gap by the
  summary builder);
* a successful query with **zero matches** produces no evidence - absence of
  records is a gap, never "benign";
* every collection of a tool payload is mapped separately (network vs DNS,
  files vs reputation, CTI vs ATT&CK), so knowledge never masquerades as
  observed activity;
* knowledge records are marked ``case-linked`` only when a case indicator,
  alert field or linked CTI report ties them to *this* investigation. T04
  ignores filters that do not apply to a collection (an indicator query reaches
  the whole ATT&CK subset), so unlinked records are tagged
  ``unlinked-knowledge`` and kept as references instead of being promoted to
  case findings;
* ``reliability`` is a fixed, documented source-class value - it is not a
  computed security confidence;
* one malformed record adds a warning and never discards the records already
  extracted.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, Final

from pydantic import ValidationError

from app.benchmark.schemas import (
    AttackTechniqueRecord,
    CTIRecord,
    DNSEvent,
    EndpointEvent,
    FileRecord,
    IOCReputationRecord,
    NetworkEvent,
)
from app.evidence.contracts import EvidenceExtractionResult, EvidenceSourceReference
from app.evidence.dedup import (
    ATTACK_RECORD_CLASS,
    DNS_RECORD_CLASS,
    ENDPOINT_RECORD_CLASS,
    FILE_RECORD_CLASS,
    IOC_REPUTATION_RECORD_CLASS,
    NETWORK_RECORD_CLASS,
    CTI_RECORD_CLASS,
    EvidenceAccumulator,
    attack_technique_identity,
    cti_record_identity,
    ioc_reputation_identity,
    telemetry_identity,
)
from app.evidence.provenance import (
    attack_technique_raw_ref,
    cti_raw_ref,
    dns_raw_ref,
    endpoint_raw_ref,
    file_raw_ref,
    ioc_reputation_raw_ref,
    network_raw_ref,
)
from app.runtime.contracts import InvestigationRun
from app.schemas.evidence import EvidenceSourceType, EvidenceType
from app.schemas.tools import ToolCall, ToolResult

TOOL_SEARCH_ENDPOINT = "search_endpoint_events"
TOOL_SEARCH_NETWORK = "search_network_activity"
TOOL_LOOKUP_FILE_REPUTATION = "lookup_file_reputation"
TOOL_LOOKUP_IOC_REPUTATION = "lookup_ioc_reputation"
TOOL_SEARCH_CTI = "search_cti"

#: Fixed source-class reliability. This is trust in the *source class*, not a
#: computed security confidence and not a verdict.
RELIABILITY_BY_SOURCE_CLASS: Final[dict[str, float]] = {
    "telemetry": 0.9,
    "reputation": 0.7,
    "threat_intelligence": 0.6,
    "attack_knowledge": 0.6,
}

TAG_SOURCE_CLASS_TELEMETRY: Final[str] = "source-class:telemetry"
TAG_SOURCE_CLASS_KNOWLEDGE: Final[str] = "source-class:knowledge"
TAG_KNOWLEDGE_REFERENCE: Final[str] = "knowledge-reference"
TAG_CASE_LINKED: Final[str] = "case-linked"
TAG_UNLINKED_KNOWLEDGE: Final[str] = "unlinked-knowledge"

#: Endpoint ``event_type`` -> evidence category.
ENDPOINT_TYPE_BY_EVENT_TYPE: Final[dict[str, EvidenceType]] = {
    "process_creation": EvidenceType.PROCESS_EXECUTION,
    "process_termination": EvidenceType.PROCESS_EXECUTION,
    "process_access": EvidenceType.PROCESS_EXECUTION,
    "file_creation": EvidenceType.FILE_ACTIVITY,
    "file_modification": EvidenceType.FILE_ACTIVITY,
    "file_deletion": EvidenceType.FILE_ACTIVITY,
    "authentication_failed": EvidenceType.AUTHENTICATION,
    "authentication_success": EvidenceType.AUTHENTICATION,
}

#: Metadata keys that are real facts for the evidence content.
SELECTED_METADATA_KEYS: Final[tuple[str, ...]] = (
    "logon_type",
    "source_ip",
    "source_workstation",
    "status",
    "auth_package",
    "service",
    "sni",
    "rule",
    "sensor",
)


def _compact(**values: Any) -> dict[str, Any]:
    """Keep the facts that exist and drop ``None`` values."""
    return {key: value for key, value in values.items() if value is not None}


def _selected_metadata(metadata: dict[str, Any], keys: Sequence[str]) -> dict[str, Any]:
    """Return the selected, present metadata facts."""
    return {
        key: metadata[key]
        for key in keys
        if key in metadata and metadata[key] is not None
    }


def _validation_reason(exc: ValidationError) -> str:
    """Short, input-free description of a validation failure."""
    issues = exc.errors(include_url=False, include_input=False)[:2]
    return "; ".join(
        f"{'.'.join(str(part) for part in issue['loc']) or '<record>'}: {issue['msg']}"
        for issue in issues
    )


def _as_dict(payload: Any) -> dict[str, Any] | None:
    return payload if isinstance(payload, dict) else None


class DeterministicEvidenceExtractor:
    """Turns a run into deduplicated, provenance-carrying evidence."""

    def __init__(self, *, case_id: str) -> None:
        self._case_id = case_id
        self._handlers = {
            TOOL_SEARCH_ENDPOINT: self._extract_endpoint_events,
            TOOL_SEARCH_NETWORK: self._extract_network_activity,
            TOOL_LOOKUP_FILE_REPUTATION: self._extract_file_reputation,
            TOOL_LOOKUP_IOC_REPUTATION: self._extract_ioc_reputation,
            TOOL_SEARCH_CTI: self._extract_cti,
        }

    @property
    def case_id(self) -> str:
        """Benchmark case this extractor reads raw refs for."""
        return self._case_id

    def extract(self, run: InvestigationRun) -> EvidenceExtractionResult:
        """Extract evidence from every successful tool result of ``run``."""
        accumulator = EvidenceAccumulator()
        warnings: list[str] = []
        processed: list[str] = []
        calls_by_id = {call.tool_call_id: call for call in run.tool_calls}
        case_indicators = self._collect_case_indicators(run, calls_by_id)
        linked_techniques: set[str] = set()

        for result in run.tool_results:
            processed.append(result.tool_result_id)
            call = calls_by_id.get(result.tool_call_id)
            if call is None:
                warnings.append(
                    f"{result.tool_result_id}: no ToolCall found for "
                    f"tool_call_id {result.tool_call_id!r}; result skipped"
                )
                continue
            if not result.success:
                continue
            handler = self._handlers.get(call.tool_name)
            if handler is None:
                warnings.append(
                    f"{result.tool_result_id}: tool {call.tool_name!r} has no evidence "
                    "mapping; payload skipped"
                )
                continue
            handler(
                accumulator=accumulator,
                warnings=warnings,
                call=call,
                result=result,
                case_indicators=case_indicators,
                linked_techniques=linked_techniques,
            )

        evidence, sources = accumulator.build(incident_id=run.incident_id)
        return EvidenceExtractionResult(
            incident_id=run.incident_id,
            case_id=self._case_id,
            evidence=evidence,
            sources=sources,
            processed_tool_result_ids=processed,
            candidate_count=accumulator.candidate_count,
            extraction_warnings=warnings,
        )

    # Case linking ------------------------------------------------------------

    def _collect_case_indicators(
        self, run: InvestigationRun, calls_by_id: dict[str, ToolCall]
    ) -> set[str]:
        """Collect the indicators and names that belong to this case.

        Sources: the alert's structured fields plus every telemetry record
        returned by the case-scoped tools. Knowledge records are deliberately
        not part of this set - they must link *to* the case, not to each other.
        """
        alert = run.alert
        indicators = {
            value.casefold()
            for value in (
                alert.src_ip,
                alert.dst_ip,
                alert.host,
                alert.user,
                alert.process_name,
            )
            if value
        }

        for result in run.tool_results:
            call = calls_by_id.get(result.tool_call_id)
            if call is None or not result.success:
                continue
            payload = _as_dict(result.data)
            if payload is None:
                continue
            if call.tool_name == TOOL_SEARCH_ENDPOINT:
                for raw in self._records(payload, "items"):
                    indicators.update(
                        value.casefold()
                        for value in (
                            raw.get("host"),
                            raw.get("user"),
                            raw.get("process_name"),
                            raw.get("parent_process_name"),
                            raw.get("file_path"),
                            raw.get("sha256"),
                        )
                        if isinstance(value, str) and value
                    )
            elif call.tool_name == TOOL_SEARCH_NETWORK:
                for raw in self._records(payload, "network_events"):
                    indicators.update(
                        value.casefold()
                        for value in (
                            raw.get("src_ip"),
                            raw.get("dst_ip"),
                            raw.get("src_host"),
                            raw.get("process_name"),
                        )
                        if isinstance(value, str) and value
                    )
                for raw in self._records(payload, "dns_events"):
                    indicators.update(
                        value.casefold()
                        for value in (
                            raw.get("query"),
                            raw.get("host"),
                            raw.get("src_ip"),
                            raw.get("response"),
                            raw.get("process_name"),
                        )
                        if isinstance(value, str) and value
                    )
            elif call.tool_name == TOOL_LOOKUP_FILE_REPUTATION:
                for raw in self._records(payload, "files"):
                    indicators.update(
                        value.casefold()
                        for value in (
                            raw.get("file_name"),
                            raw.get("path"),
                            raw.get("sha256"),
                            raw.get("host"),
                        )
                        if isinstance(value, str) and value
                    )
        return indicators

    @staticmethod
    def _records(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
        value = payload.get(key)
        if not isinstance(value, list):
            return []
        return [entry for entry in value if isinstance(entry, dict)]

    @staticmethod
    def _is_case_linked(indicator: str, case_indicators: Iterable[str]) -> bool:
        return indicator.casefold() in case_indicators

    # Handlers ----------------------------------------------------------------

    def _extract_endpoint_events(self, **context: Any) -> None:
        accumulator, warnings = context["accumulator"], context["warnings"]
        call, result = context["call"], context["result"]
        payload = self._payload(call, result, warnings)
        if payload is None:
            return
        if not isinstance(payload.get("items"), list):
            warnings.append(
                f"{result.tool_result_id}: unsupported payload for {call.tool_name!r}: "
                "missing list 'items'"
            )
            return

        for raw in payload["items"]:
            try:
                event = EndpointEvent.model_validate(raw)
            except ValidationError as exc:
                warnings.append(
                    f"{result.tool_result_id}: invalid EndpointEvent in 'items': "
                    f"{_validation_reason(exc)}"
                )
                continue
            content = _compact(
                record_class=ENDPOINT_RECORD_CLASS,
                record_id=event.event_id,
                event_type=event.event_type,
                host=event.host,
                user=event.user,
                process_name=event.process_name,
                pid=event.pid,
                parent_process_name=event.parent_process_name,
                command_line=event.command_line,
                file_path=event.file_path,
                sha256=event.sha256,
            )
            content.update(_selected_metadata(event.metadata, SELECTED_METADATA_KEYS))
            accumulator.add(
                identity=telemetry_identity(ENDPOINT_RECORD_CLASS, event.event_id),
                evidence_type=ENDPOINT_TYPE_BY_EVENT_TYPE.get(
                    event.event_type, EvidenceType.OTHER
                ),
                summary=self._endpoint_summary(event),
                content=content,
                observed_at=event.timestamp,
                collected_at=result.returned_at,
                reliability=RELIABILITY_BY_SOURCE_CLASS["telemetry"],
                tags=[TAG_SOURCE_CLASS_TELEMETRY, f"tool:{call.tool_name}"],
                reference=self._reference(
                    call=call,
                    result=result,
                    record_id=event.event_id,
                    raw_ref=endpoint_raw_ref(self._case_id, event.event_id),
                    content=content,
                ),
            )

    def _extract_network_activity(self, **context: Any) -> None:
        accumulator, warnings = context["accumulator"], context["warnings"]
        call, result = context["call"], context["result"]
        payload = self._payload(call, result, warnings)
        if payload is None:
            return

        for collection, schema, record_class, raw_ref_builder, summary_builder in (
            (
                "network_events",
                NetworkEvent,
                NETWORK_RECORD_CLASS,
                network_raw_ref,
                self._network_summary,
            ),
            (
                "dns_events",
                DNSEvent,
                DNS_RECORD_CLASS,
                dns_raw_ref,
                self._dns_summary,
            ),
        ):
            if not isinstance(payload.get(collection), list):
                warnings.append(
                    f"{result.tool_result_id}: unsupported payload for {call.tool_name!r}: "
                    f"missing list {collection!r}"
                )
                continue
            for raw in payload[collection]:
                try:
                    record = schema.model_validate(raw)
                except ValidationError as exc:
                    warnings.append(
                        f"{result.tool_result_id}: invalid {schema.__name__} in "
                        f"{collection!r}: {_validation_reason(exc)}"
                    )
                    continue
                if isinstance(record, NetworkEvent):
                    content = _compact(
                        record_class=NETWORK_RECORD_CLASS,
                        record_id=record.event_id,
                        src_host=record.src_host,
                        src_ip=record.src_ip,
                        src_port=record.src_port,
                        dst_ip=record.dst_ip,
                        dst_port=record.dst_port,
                        protocol=record.protocol,
                        direction=record.direction,
                        bytes_sent=record.bytes_sent,
                        bytes_received=record.bytes_received,
                        process_name=record.process_name,
                    )
                    content.update(_selected_metadata(record.metadata, SELECTED_METADATA_KEYS))
                    evidence_type = EvidenceType.NETWORK_CONNECTION
                    summary = self._network_summary(record)
                else:
                    content = _compact(
                        record_class=DNS_RECORD_CLASS,
                        record_id=record.event_id,
                        host=record.host,
                        src_ip=record.src_ip,
                        query=record.query,
                        query_type=record.record_type,
                        response=record.response,
                        process_name=record.process_name,
                    )
                    evidence_type = EvidenceType.DNS_QUERY
                    summary = self._dns_summary(record)

                accumulator.add(
                    identity=telemetry_identity(record_class, record.event_id),
                    evidence_type=evidence_type,
                    summary=summary,
                    content=content,
                    observed_at=record.timestamp,
                    collected_at=result.returned_at,
                    reliability=RELIABILITY_BY_SOURCE_CLASS["telemetry"],
                    tags=[TAG_SOURCE_CLASS_TELEMETRY, f"tool:{call.tool_name}"],
                    reference=self._reference(
                        call=call,
                        result=result,
                        record_id=record.event_id,
                        raw_ref=raw_ref_builder(self._case_id, record.event_id),
                        content=content,
                    ),
                )

    def _extract_file_reputation(self, **context: Any) -> None:
        accumulator, warnings = context["accumulator"], context["warnings"]
        call, result = context["call"], context["result"]
        payload = self._payload(call, result, warnings)
        if payload is None:
            return

        if not isinstance(payload.get("files"), list):
            warnings.append(
                f"{result.tool_result_id}: unsupported payload for {call.tool_name!r}: "
                "missing list 'files'"
            )
        else:
            for raw in payload["files"]:
                try:
                    record = FileRecord.model_validate(raw)
                except ValidationError as exc:
                    warnings.append(
                        f"{result.tool_result_id}: invalid FileRecord in 'files': "
                        f"{_validation_reason(exc)}"
                    )
                    continue
                content = _compact(
                    record_class=FILE_RECORD_CLASS,
                    record_id=record.file_id,
                    host=record.host,
                    path=record.path,
                    file_name=record.file_name,
                    sha256=record.sha256,
                    size=record.size,
                    signed=record.signed,
                    signer=record.signer,
                    source_url=record.source_url,
                )
                accumulator.add(
                    identity=telemetry_identity(FILE_RECORD_CLASS, record.file_id),
                    evidence_type=EvidenceType.FILE_ACTIVITY,
                    summary=self._file_summary(record),
                    content=content,
                    observed_at=record.timestamp,
                    collected_at=result.returned_at,
                    reliability=RELIABILITY_BY_SOURCE_CLASS["telemetry"],
                    tags=[TAG_SOURCE_CLASS_TELEMETRY, f"tool:{call.tool_name}"],
                    reference=self._reference(
                        call=call,
                        result=result,
                        record_id=record.file_id,
                        raw_ref=file_raw_ref(self._case_id, record.file_id),
                        content=content,
                    ),
                )

        if not isinstance(payload.get("reputations"), list):
            warnings.append(
                f"{result.tool_result_id}: unsupported payload for {call.tool_name!r}: "
                "missing list 'reputations'"
            )
            return
        for raw in payload["reputations"]:
            self._add_reputation(
                accumulator=accumulator,
                warnings=warnings,
                call=call,
                result=result,
                raw=raw,
                case_indicators=context["case_indicators"],
                linked_by_construction=True,
            )

    def _extract_ioc_reputation(self, **context: Any) -> None:
        accumulator, warnings = context["accumulator"], context["warnings"]
        call, result = context["call"], context["result"]
        payload = self._payload(call, result, warnings)
        if payload is None:
            return
        if not isinstance(payload.get("records"), list):
            warnings.append(
                f"{result.tool_result_id}: unsupported payload for {call.tool_name!r}: "
                "missing list 'records'"
            )
            return
        for raw in payload["records"]:
            self._add_reputation(
                accumulator=accumulator,
                warnings=warnings,
                call=call,
                result=result,
                raw=raw,
                case_indicators=context["case_indicators"],
                linked_by_construction=False,
            )

    def _extract_cti(self, **context: Any) -> None:
        accumulator, warnings = context["accumulator"], context["warnings"]
        call, result = context["call"], context["result"]
        case_indicators = context["case_indicators"]
        linked_techniques: set[str] = context["linked_techniques"]
        payload = self._payload(call, result, warnings)
        if payload is None:
            return

        if not isinstance(payload.get("cti_records"), list):
            warnings.append(
                f"{result.tool_result_id}: unsupported payload for {call.tool_name!r}: "
                "missing list 'cti_records'"
            )
        else:
            for raw in payload["cti_records"]:
                try:
                    record = CTIRecord.model_validate(raw)
                except ValidationError as exc:
                    warnings.append(
                        f"{result.tool_result_id}: invalid CTIRecord in 'cti_records': "
                        f"{_validation_reason(exc)}"
                    )
                    continue
                linked = any(
                    self._is_case_linked(indicator, case_indicators)
                    for indicator in record.indicators
                )
                if linked:
                    linked_techniques.update(record.technique_ids)
                content = _compact(
                    record_class=CTI_RECORD_CLASS,
                    record_id=record.cti_id,
                    cti_id=record.cti_id,
                    title=record.title,
                    description=record.summary,
                    indicators=record.indicators,
                    malware_families=record.malware_families,
                    campaigns=record.campaigns,
                    technique_ids=record.technique_ids,
                    source=record.source,
                    published_at=record.published_at.isoformat(),
                )
                accumulator.add(
                    identity=cti_record_identity(record),
                    evidence_type=EvidenceType.THREAT_INTELLIGENCE,
                    summary=self._cti_summary(record, linked=linked),
                    content=content,
                    observed_at=record.published_at,
                    collected_at=result.returned_at,
                    reliability=RELIABILITY_BY_SOURCE_CLASS["threat_intelligence"],
                    tags=self._knowledge_tags(
                        tool_name=call.tool_name,
                        linked=linked,
                        extra=(TAG_KNOWLEDGE_REFERENCE,),
                    ),
                    reference=self._reference(
                        call=call,
                        result=result,
                        record_id=record.cti_id,
                        raw_ref=cti_raw_ref(record.cti_id),
                        content=content,
                    ),
                )

        if not isinstance(payload.get("attack_techniques"), list):
            warnings.append(
                f"{result.tool_result_id}: unsupported payload for {call.tool_name!r}: "
                "missing list 'attack_techniques'"
            )
            return
        for raw in payload["attack_techniques"]:
            try:
                technique = AttackTechniqueRecord.model_validate(raw)
            except ValidationError as exc:
                warnings.append(
                    f"{result.tool_result_id}: invalid AttackTechniqueRecord in "
                    f"'attack_techniques': {_validation_reason(exc)}"
                )
                continue
            linked = technique.technique_id in linked_techniques
            content = _compact(
                record_class=ATTACK_RECORD_CLASS,
                record_id=technique.technique_id,
                technique_id=technique.technique_id,
                name=technique.name,
                description=technique.description,
                tactics=technique.tactics,
                keywords=technique.keywords,
            )
            accumulator.add(
                identity=attack_technique_identity(technique),
                evidence_type=EvidenceType.ATTACK_KNOWLEDGE,
                summary=self._attack_summary(technique, linked=linked),
                content=content,
                observed_at=None,
                collected_at=result.returned_at,
                reliability=RELIABILITY_BY_SOURCE_CLASS["attack_knowledge"],
                tags=self._knowledge_tags(
                    tool_name=call.tool_name,
                    linked=linked,
                    extra=(TAG_KNOWLEDGE_REFERENCE,),
                ),
                reference=self._reference(
                    call=call,
                    result=result,
                    record_id=technique.technique_id,
                    raw_ref=attack_technique_raw_ref(technique.technique_id),
                    content=content,
                ),
            )

    # Shared helpers ----------------------------------------------------------

    def _add_reputation(
        self,
        *,
        accumulator: EvidenceAccumulator,
        warnings: list[str],
        call: ToolCall,
        result: ToolResult,
        raw: Any,
        case_indicators: Iterable[str],
        linked_by_construction: bool,
    ) -> None:
        try:
            record = IOCReputationRecord.model_validate(raw)
        except ValidationError as exc:
            warnings.append(
                f"{result.tool_result_id}: invalid IOCReputationRecord: "
                f"{_validation_reason(exc)}"
            )
            return
        # A record is linked to the case when it backs a case-scoped query
        # (enrichment of a matched file, or the indicator this call requested) or
        # when its indicator also appears in the case telemetry.
        requested_indicator = call.arguments.get("indicator")
        linked = (
            linked_by_construction
            or self._is_case_linked(record.indicator, case_indicators)
            or (
                isinstance(requested_indicator, str)
                and requested_indicator.casefold() == record.indicator.casefold()
            )
        )
        content = _compact(
            record_class=IOC_REPUTATION_RECORD_CLASS,
            record_id=f"{record.indicator}|{record.source}",
            indicator=record.indicator,
            indicator_type=record.indicator_type.value,
            reputation=record.reputation.value,
            source=record.source,
            source_confidence=record.confidence,
            asserted_tags=list(record.tags),
            last_seen=record.last_seen.isoformat() if record.last_seen else None,
        )
        accumulator.add(
            identity=ioc_reputation_identity(record),
            evidence_type=EvidenceType.IOC_REPUTATION,
            summary=self._reputation_summary(record),
            content=content,
            observed_at=record.last_seen,
            collected_at=result.returned_at,
            reliability=RELIABILITY_BY_SOURCE_CLASS["reputation"],
            tags=self._knowledge_tags(
                tool_name=call.tool_name,
                linked=linked,
                extra=(f"reputation:{record.reputation.value}",),
            ),
            reference=self._reference(
                call=call,
                result=result,
                record_id=f"{record.indicator}|{record.source}",
                raw_ref=ioc_reputation_raw_ref(record.indicator, record.source),
                content=content,
            ),
        )

    @staticmethod
    def _knowledge_tags(
        *, tool_name: str, linked: bool, extra: Sequence[str] = ()
    ) -> list[str]:
        tags = [TAG_SOURCE_CLASS_KNOWLEDGE, f"tool:{tool_name}"]
        tags.extend(extra)
        tags.append(TAG_CASE_LINKED if linked else TAG_UNLINKED_KNOWLEDGE)
        return tags

    def _payload(
        self, call: ToolCall, result: ToolResult, warnings: list[str]
    ) -> dict[str, Any] | None:
        payload = _as_dict(result.data)
        if payload is None:
            warnings.append(
                f"{result.tool_result_id}: unsupported payload for {call.tool_name!r}: "
                f"expected a JSON object, got {type(result.data).__name__}"
            )
        return payload

    @staticmethod
    def _reference(
        *,
        call: ToolCall,
        result: ToolResult,
        record_id: str,
        raw_ref: str,
        content: dict[str, Any],
    ) -> EvidenceSourceReference:
        return EvidenceSourceReference(
            source_type=EvidenceSourceType.TOOL,
            source_name=call.tool_name,
            tool_call_id=call.tool_call_id,
            tool_result_id=result.tool_result_id,
            record_id=record_id,
            raw_ref=raw_ref,
            source_fields=sorted(key for key in content if key != "record_class"),
        )

    # Summaries ---------------------------------------------------------------

    @staticmethod
    def _endpoint_summary(event: EndpointEvent) -> str:
        parts = [f"Host {event.host}: {event.event_type}"]
        if event.process_name:
            parts.append(f"process {event.process_name}")
        if event.parent_process_name:
            parts.append(f"parent {event.parent_process_name}")
        if event.user:
            parts.append(f"user {event.user}")
        if event.file_path:
            parts.append(f"path {event.file_path}")
        elif event.command_line:
            parts.append("command line recorded")
        return ", ".join(parts)

    @staticmethod
    def _network_summary(event: NetworkEvent) -> str:
        source = event.src_host or event.src_ip
        origin = f"{event.src_ip}:{event.src_port}" if event.src_port else event.src_ip
        parts = [
            f"Host {source}: {event.direction} {event.protocol} flow {origin} -> "
            f"{event.dst_ip}:{event.dst_port}"
        ]
        if event.process_name:
            parts.append(f"process {event.process_name}")
        return ", ".join(parts)

    @staticmethod
    def _dns_summary(event: DNSEvent) -> str:
        parts = [
            f"Host {event.host}: DNS {event.record_type} query for {event.query} "
            f"from {event.src_ip}"
        ]
        parts.append(f"answer {event.response}" if event.response else "no answer recorded")
        if event.process_name:
            parts.append(f"process {event.process_name}")
        return ", ".join(parts)

    @staticmethod
    def _file_summary(record: FileRecord) -> str:
        parts = [f"Host {record.host}: file {record.file_name} recorded at {record.path}"]
        parts.append("hash recorded" if record.sha256 else "no hash recorded in telemetry")
        if record.signed is True:
            parts.append(f"signed by {record.signer}" if record.signer else "signed")
        elif record.signed is False:
            parts.append("not signed")
        if record.source_url:
            parts.append(f"downloaded from {record.source_url}")
        return ", ".join(parts)

    @staticmethod
    def _reputation_summary(record: IOCReputationRecord) -> str:
        summary = (
            f"Reputation reference: {record.indicator} "
            f"({record.indicator_type.value}) reported '{record.reputation.value}' by "
            f"{record.source}"
        )
        if record.reputation.value == "unknown":
            summary += " - no assessment available"
        return summary

    @staticmethod
    def _cti_summary(record: CTIRecord, *, linked: bool) -> str:
        summary = f"CTI knowledge reference {record.cti_id}: {record.title}"
        if record.campaigns:
            summary += f" (campaigns: {', '.join(record.campaigns)})"
        summary += (
            " - reference only, not confirmed activity in this case"
            if linked
            else " - not linked to a case indicator; reference only"
        )
        return summary

    @staticmethod
    def _attack_summary(record: AttackTechniqueRecord, *, linked: bool) -> str:
        summary = (
            f"ATT&CK knowledge reference {record.technique_id}: {record.name} - "
            "knowledge entry only, not a confirmed technique usage"
        )
        if not linked:
            summary += " (not linked to a case indicator)"
        return summary
