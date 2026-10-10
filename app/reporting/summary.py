"""Deterministic summary builder.

Input: an :class:`~app.runtime.contracts.InvestigationRun` (execution metadata
only) plus the :class:`~app.evidence.contracts.EvidenceExtractionResult`.
Output: an :class:`~app.reporting.contracts.InvestigationSummary`.

Rules:

* observations are grouped facts with stable group keys, sorted for
  reproducibility; each one references only evidence that exists;
* knowledge evidence is summarised as a *reference*; unlinked knowledge becomes
  an information gap instead of an observation;
* gaps cover failed tools, empty results, unknown reputation, missing results,
  failed steps and early stops - always phrased as missing data, never as
  evidence of benign activity;
* no verdict, severity or confidence is produced.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any, Final

from app.evidence.contracts import EvidenceExtractionResult
from app.evidence.dedup import (
    ENDPOINT_RECORD_CLASS,
    FILE_RECORD_CLASS,
)
from app.evidence.extractor import (
    TAG_UNLINKED_KNOWLEDGE,
    TOOL_LOOKUP_FILE_REPUTATION,
    TOOL_LOOKUP_IOC_REPUTATION,
    TOOL_SEARCH_CTI,
    TOOL_SEARCH_ENDPOINT,
    TOOL_SEARCH_NETWORK,
)
from app.reporting.contracts import (
    InvestigationSummary,
    SummaryObservation,
    SummaryObservationCategory,
)
from app.runtime.contracts import InvestigationRun, RuntimeStatus
from app.schemas.evidence import Evidence, EvidenceType
from app.schemas.investigation import InvestigationStepStatus
from app.schemas.tools import ToolResult

#: Fixed, honest description of what this MVP does and does not do.
LIMITATIONS: Final[tuple[str, ...]] = (
    "Deterministic MVP: no LLM, no retrieval augmentation and no autonomous reasoning "
    "is involved in this summary.",
    "No verdict, severity, risk score or confidence is produced; evidence reliability is "
    "a fixed source-class value, not a computed security confidence.",
    "IOC reputation, CTI and ATT&CK records are references from synthetic shared "
    "knowledge; they are not proof that the described behaviour occurred in this case.",
    "Coverage is limited to the benchmark dataset shipped for this case; telemetry that "
    "is not part of the dataset cannot appear as evidence.",
    "Absence of matching records is reported as an information gap and never as evidence "
    "of benign activity.",
)

MAX_LISTED_IDS: Final[int] = 6


def _unique_sorted(values: Iterable[Any]) -> list[str]:
    return sorted({str(value) for value in values if value not in (None, "")})


def _limited(values: Sequence[str], limit: int = MAX_LISTED_IDS) -> str:
    listed = list(values[:limit])
    if len(values) > limit:
        listed.append(f"and {len(values) - limit} more")
    return ", ".join(listed)


def _group(
    evidence: Iterable[Evidence], key_of: Callable[[Evidence], tuple[str, ...]]
) -> list[tuple[tuple[str, ...], list[Evidence]]]:
    groups: dict[tuple[str, ...], list[Evidence]] = {}
    for item in evidence:
        groups.setdefault(key_of(item), []).append(item)
    return [(key, groups[key]) for key in sorted(groups)]


def _content(item: Evidence, key: str) -> str | None:
    value = item.content.get(key)
    return value if isinstance(value, str) and value else None


def _content_list(items: Iterable[Evidence], key: str) -> list[str]:
    return _unique_sorted(_content(item, key) for item in items)


def _record_ids(items: Sequence[Evidence]) -> list[str]:
    return _unique_sorted(_content(item, "record_id") for item in items)


def _by_record_class(
    extraction: EvidenceExtractionResult, evidence_type: EvidenceType, record_class: str
) -> list[Evidence]:
    return [
        item
        for item in extraction.evidence_of_type(evidence_type)
        if _content(item, "record_class") == record_class
    ]


def _linked(evidence: Iterable[Evidence]) -> list[Evidence]:
    return [item for item in evidence if TAG_UNLINKED_KNOWLEDGE not in item.tags]


class DeterministicSummaryBuilder:
    """Builds an :class:`InvestigationSummary` from a run and its evidence."""

    def build(
        self, run: InvestigationRun, extraction: EvidenceExtractionResult
    ) -> InvestigationSummary:
        """Return the deterministic summary of ``run``."""
        observations: list[SummaryObservation] = []
        observations.extend(self._endpoint_observations(extraction))
        observations.extend(self._network_observations(extraction))
        observations.extend(self._dns_observations(extraction))
        observations.extend(self._file_observations(extraction))
        observations.extend(self._authentication_observations(extraction))
        observations.extend(self._reputation_observations(extraction))
        observations.extend(self._cti_observations(extraction))
        observations.extend(self._attack_observations(extraction))

        unlinked = [
            item.evidence_id
            for item in extraction.evidence
            if TAG_UNLINKED_KNOWLEDGE in item.tags
        ]
        gaps = self._information_gaps(run, extraction, unlinked)

        return InvestigationSummary(
            incident_id=run.incident_id,
            case_id=extraction.case_id,
            status=run.status,
            stop_reason=run.stop_reason,
            tool_call_count=len(run.tool_calls),
            evidence_count=extraction.evidence_count,
            observations=observations,
            information_gaps=gaps,
            limitations=list(LIMITATIONS),
            evidence_type_counts=extraction.evidence_type_counts,
            evidence_ids=extraction.evidence_ids(),
            unlinked_knowledge_evidence_ids=unlinked,
            generated_at=run.completed_at,
        )

    # Observations ------------------------------------------------------------

    def _endpoint_observations(
        self, extraction: EvidenceExtractionResult
    ) -> list[SummaryObservation]:
        observations: list[SummaryObservation] = []
        process_evidence = _by_record_class(
            extraction, EvidenceType.PROCESS_EXECUTION, ENDPOINT_RECORD_CLASS
        )
        for _key, items in _group(
            process_evidence,
            key_of=lambda item: (
                _content(item, "host") or "",
                _content(item, "process_name") or "",
                _content(item, "parent_process_name") or "",
            ),
        ):
            host = _content(items[0], "host") or "unknown host"
            process = _content(items[0], "process_name") or "unknown process"
            parent = _content(items[0], "parent_process_name")
            description = (
                f"{len(items)} endpoint event(s) recorded for process {process} on host {host}"
            )
            if parent:
                description += f" with parent process {parent}"
            users = _content_list(items, "user")
            if users:
                description += f"; users {', '.join(users)}"
            event_types = _content_list(items, "event_type")
            description += f"; event types {', '.join(event_types)}"
            command_lines = [item for item in items if _content(item, "command_line")]
            if command_lines:
                description += (
                    f"; a command line is recorded in {len(command_lines)} of these records"
                )
            description += f". Records: {_limited(_record_ids(items))}."
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.OBSERVED_ACTIVITY,
                    title=f"Process activity on {host}: {process}",
                    description=description,
                    evidence_ids=[item.evidence_id for item in items],
                )
            )

        other_evidence = _by_record_class(
            extraction, EvidenceType.OTHER, ENDPOINT_RECORD_CLASS
        )
        for _key, items in _group(
            other_evidence,
            key_of=lambda item: (
                _content(item, "host") or "",
                _content(item, "event_type") or "",
            ),
        ):
            event_type = _content(items[0], "event_type") or "unknown event type"
            host = _content(items[0], "host") or "unknown host"
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.OBSERVED_ACTIVITY,
                    title=f"Endpoint event on {host}: {event_type}",
                    description=(
                        f"{len(items)} endpoint event(s) of type {event_type} recorded on "
                        f"host {host}. Records: {_limited(_record_ids(items))}."
                    ),
                    evidence_ids=[item.evidence_id for item in items],
                )
            )
        return observations

    def _network_observations(
        self, extraction: EvidenceExtractionResult
    ) -> list[SummaryObservation]:
        observations: list[SummaryObservation] = []
        for _key, items in _group(
            extraction.evidence_of_type(EvidenceType.NETWORK_CONNECTION),
            key_of=lambda item: (
                _content(item, "dst_ip") or "",
                str(item.content.get("dst_port", "")),
                _content(item, "protocol") or "",
                _content(item, "direction") or "",
            ),
        ):
            destination = _content(items[0], "dst_ip") or "unknown destination"
            port = items[0].content.get("dst_port")
            port_label = f":{port}" if port is not None else ""
            protocol = _content(items[0], "protocol") or "unknown protocol"
            direction = _content(items[0], "direction") or "unknown direction"
            sources = _content_list(items, "src_ip")
            processes = _content_list(items, "process_name")
            description = (
                f"{len(items)} {direction} {protocol} flow record(s) to {destination}{port_label}"
            )
            if sources:
                description += f" from {', '.join(sources)}"
            if processes:
                description += f"; processes {', '.join(processes)}"
            description += f". Records: {_limited(_record_ids(items))}."
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.OBSERVED_ACTIVITY,
                    title=f"Network flow to {destination}{port_label}",
                    description=description,
                    evidence_ids=[item.evidence_id for item in items],
                )
            )
        return observations

    def _dns_observations(
        self, extraction: EvidenceExtractionResult
    ) -> list[SummaryObservation]:
        observations: list[SummaryObservation] = []
        for _key, items in _group(
            extraction.evidence_of_type(EvidenceType.DNS_QUERY),
            key_of=lambda item: (
                _content(item, "query") or "",
                _content(item, "query_type") or "",
            ),
        ):
            query = _content(items[0], "query") or "unknown query"
            query_type = _content(items[0], "query_type") or "unknown type"
            hosts = _content_list(items, "host")
            answers = _content_list(items, "response")
            processes = _content_list(items, "process_name")
            description = f"{len(items)} DNS {query_type} query record(s) for {query}"
            if hosts:
                description += f" from host(s) {', '.join(hosts)}"
            description += (
                f"; recorded answers {', '.join(answers)}"
                if answers
                else "; no answer recorded in telemetry"
            )
            if processes:
                description += f"; processes {', '.join(processes)}"
            description += f". Records: {_limited(_record_ids(items))}."
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.OBSERVED_ACTIVITY,
                    title=f"DNS query: {query}",
                    description=description,
                    evidence_ids=[item.evidence_id for item in items],
                )
            )
        return observations

    def _file_observations(
        self, extraction: EvidenceExtractionResult
    ) -> list[SummaryObservation]:
        observations: list[SummaryObservation] = []
        for _key, items in _group(
            _by_record_class(extraction, EvidenceType.FILE_ACTIVITY, FILE_RECORD_CLASS),
            key_of=lambda item: (
                _content(item, "host") or "",
                _content(item, "file_name") or "",
            ),
        ):
            file_name = _content(items[0], "file_name") or "unknown file"
            host = _content(items[0], "host") or "unknown host"
            parts = [f"{len(items)} file telemetry record(s) for {file_name} on host {host}"]
            paths = _content_list(items, "path")
            if paths:
                parts.append(f"paths {', '.join(paths)}")
            hashes = _content_list(items, "sha256")
            parts.append(
                f"SHA256 {', '.join(hashes)}" if hashes else "no SHA256 recorded in telemetry"
            )
            signers = _content_list(items, "signer")
            if signers:
                parts.append(f"signers {', '.join(signers)}")
            sources = _content_list(items, "source_url")
            if sources:
                parts.append(f"download sources {', '.join(sources)}")
            parts.append(f"records {_limited(_record_ids(items))}")
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.OBSERVED_ACTIVITY,
                    title=f"File artifact: {file_name} on {host}",
                    description="; ".join(parts) + ".",
                    evidence_ids=[item.evidence_id for item in items],
                )
            )

        for _key, items in _group(
            _by_record_class(extraction, EvidenceType.FILE_ACTIVITY, ENDPOINT_RECORD_CLASS),
            key_of=lambda item: (
                _content(item, "host") or "",
                _content(item, "event_type") or "",
                _content(item, "file_path") or "",
            ),
        ):
            event_type = _content(items[0], "event_type") or "file event"
            host = _content(items[0], "host") or "unknown host"
            paths = _content_list(items, "file_path")
            processes = _content_list(items, "process_name")
            description = f"{len(items)} endpoint {event_type} record(s) on host {host}"
            if paths:
                description += f" for {', '.join(paths)}"
            if processes:
                description += f"; processes {', '.join(processes)}"
            description += f". Records: {_limited(_record_ids(items))}."
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.OBSERVED_ACTIVITY,
                    title=f"Endpoint file activity on {host}: {event_type}",
                    description=description,
                    evidence_ids=[item.evidence_id for item in items],
                )
            )
        return observations

    def _authentication_observations(
        self, extraction: EvidenceExtractionResult
    ) -> list[SummaryObservation]:
        observations: list[SummaryObservation] = []
        for _key, items in _group(
            extraction.evidence_of_type(EvidenceType.AUTHENTICATION),
            key_of=lambda item: (
                _content(item, "host") or "",
                _content(item, "user") or "",
                _content(item, "event_type") or "",
            ),
        ):
            host = _content(items[0], "host") or "unknown host"
            user = _content(items[0], "user") or "unknown user"
            event_type = _content(items[0], "event_type") or "authentication event"
            description = f"{len(items)} {event_type} record(s) for user {user} on host {host}"
            source_ips = _content_list(items, "source_ip")
            if source_ips:
                description += f"; source IPs {', '.join(source_ips)}"
            logon_types = _content_list(items, "logon_type")
            if logon_types:
                description += f"; logon types {', '.join(logon_types)}"
            description += f". Records: {_limited(_record_ids(items))}."
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.OBSERVED_ACTIVITY,
                    title=f"Authentication activity: {event_type} for {user} on {host}",
                    description=description,
                    evidence_ids=[item.evidence_id for item in items],
                )
            )
        return observations

    def _reputation_observations(
        self, extraction: EvidenceExtractionResult
    ) -> list[SummaryObservation]:
        observations: list[SummaryObservation] = []
        for _key, items in _group(
            _linked(extraction.evidence_of_type(EvidenceType.IOC_REPUTATION)),
            key_of=lambda item: (
                _content(item, "indicator") or "",
                _content(item, "reputation") or "",
                _content(item, "source") or "",
            ),
        ):
            indicator = _content(items[0], "indicator") or "unknown indicator"
            reputation = _content(items[0], "reputation") or "unknown"
            sources = _content_list(items, "source")
            confidence = items[0].content.get("source_confidence")
            description = f"{indicator} is reported as '{reputation}' by {', '.join(sources)}"
            if confidence is not None:
                description += f" (source confidence {confidence})"
            description += (
                ". This is a reputation reference from shared knowledge, not an "
                "observation of activity in this case"
            )
            if reputation == "unknown":
                description += "; no assessment is available for this indicator"
            description += "."
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.REPUTATION_INTELLIGENCE,
                    title=f"Reputation reference: {indicator} ({reputation})",
                    description=description,
                    evidence_ids=[item.evidence_id for item in items],
                )
            )
        return observations

    def _cti_observations(
        self, extraction: EvidenceExtractionResult
    ) -> list[SummaryObservation]:
        observations: list[SummaryObservation] = []
        for _key, items in _group(
            _linked(extraction.evidence_of_type(EvidenceType.THREAT_INTELLIGENCE)),
            key_of=lambda item: (_content(item, "cti_id") or _content(item, "record_id") or "",),
        ):
            cti_id = _content(items[0], "cti_id") or _content(items[0], "record_id")
            cti_id = cti_id or "unknown report"
            title = _content(items[0], "title") or "untitled report"
            sources = _content_list(items, "source")
            indicators = items[0].content.get("indicators")
            technique_ids = items[0].content.get("technique_ids")
            description = f"CTI report {cti_id} ('{title}')"
            if sources:
                description += f" from {', '.join(sources)}"
            if isinstance(indicators, list) and indicators:
                description += (
                    f" lists indicators {_limited([str(value) for value in indicators])}"
                )
            if isinstance(technique_ids, list) and technique_ids:
                description += (
                    f" and techniques {_limited([str(value) for value in technique_ids])}"
                )
            description += (
                ". The report is linked to case indicators but remains a knowledge "
                "reference: it does not confirm that the described activity occurred here."
            )
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.CTI_KNOWLEDGE_REFERENCE,
                    title=f"CTI knowledge reference: {cti_id}",
                    description=description,
                    evidence_ids=[item.evidence_id for item in items],
                )
            )
        return observations

    def _attack_observations(
        self, extraction: EvidenceExtractionResult
    ) -> list[SummaryObservation]:
        observations: list[SummaryObservation] = []
        for _key, items in _group(
            _linked(extraction.evidence_of_type(EvidenceType.ATTACK_KNOWLEDGE)),
            key_of=lambda item: (_content(item, "technique_id") or "",),
        ):
            technique_id = _content(items[0], "technique_id") or "unknown technique"
            name = _content(items[0], "name") or "unnamed technique"
            tactics = items[0].content.get("tactics")
            description = f"ATT&CK entry {technique_id} ('{name}')"
            if isinstance(tactics, list) and tactics:
                description += f" with tactics {_limited([str(value) for value in tactics])}"
            description += (
                ". This entry is referenced by a CTI report linked to case indicators; it "
                "is knowledge, not a confirmed technique usage in this case."
            )
            observations.append(
                SummaryObservation(
                    category=SummaryObservationCategory.ATTACK_KNOWLEDGE_REFERENCE,
                    title=f"ATT&CK knowledge reference: {technique_id}",
                    description=description,
                    evidence_ids=[item.evidence_id for item in items],
                )
            )
        return observations

    # Gaps --------------------------------------------------------------------

    def _information_gaps(
        self,
        run: InvestigationRun,
        extraction: EvidenceExtractionResult,
        unlinked_knowledge_ids: Sequence[str],
    ) -> list[str]:
        gaps: list[str] = []
        calls_by_id = {call.tool_call_id: call for call in run.tool_calls}

        if run.plan is None:
            gaps.append(
                f"The planner did not produce a plan (stop reason '{run.stop_reason.value}'), "
                "so no investigation step and no tool call was executed."
            )
        else:
            for step in run.plan.steps:
                if step.status is InvestigationStepStatus.FAILED:
                    gaps.append(
                        f"Step {step.step_id} ({step.action}) ended failed: "
                        f"{step.error or 'no reason recorded'}; coverage is incomplete."
                    )

        results_by_call: dict[str, ToolResult] = {}
        for result in run.tool_results:
            results_by_call[result.tool_call_id] = result
            call = calls_by_id.get(result.tool_call_id)
            tool_name = call.tool_name if call is not None else result.tool_name
            if not result.success:
                gaps.append(
                    f"Tool '{tool_name}' failed for tool call {result.tool_call_id} "
                    f"(result {result.tool_result_id}): "
                    f"{result.error or 'no error message'}; no facts were extracted from it."
                )
                continue
            gaps.extend(self._empty_result_gaps(tool_name, result))

        for call in run.tool_calls:
            if call.tool_call_id not in results_by_call:
                gaps.append(
                    f"Tool call {call.tool_call_id} ('{call.tool_name}') produced no "
                    "ToolResult (executor exception); the attempt is recorded in the "
                    "trajectory and no facts are available from it."
                )

        if unlinked_knowledge_ids:
            gaps.append(
                f"{len(unlinked_knowledge_ids)} knowledge record(s) were returned without a "
                "case link (for example a query whose filter does not apply to that "
                "collection) and are kept as references only: "
                f"{_limited(list(unlinked_knowledge_ids))}; they are not findings about "
                "this case."
            )

        if run.status is not RuntimeStatus.COMPLETED:
            gaps.append(
                f"The investigation stopped with status '{run.status.value}' and reason "
                f"'{run.stop_reason.value}'; results are partial."
            )

        if extraction.evidence_count == 0:
            gaps.append(
                "No evidence could be extracted from the tool results of this "
                "investigation; this says nothing about whether the activity was benign."
            )
        return gaps

    def _empty_result_gaps(self, tool_name: str, result: ToolResult) -> list[str]:
        payload = result.data if isinstance(result.data, dict) else {}
        reference = f"tool call {result.tool_call_id} (result {result.tool_result_id})"
        suffix = "Absence of matching data is not evidence of benign activity."
        gaps: list[str] = []

        if tool_name == TOOL_SEARCH_ENDPOINT:
            if payload.get("count") == 0:
                gaps.append(
                    f"Endpoint search {reference} returned no matching events. {suffix}"
                )
        elif tool_name == TOOL_SEARCH_NETWORK:
            if payload.get("network_count") == 0:
                gaps.append(
                    f"Network search {reference} returned no matching flow records. {suffix}"
                )
            if payload.get("dns_count") == 0:
                gaps.append(
                    f"Network search {reference} returned no matching DNS records. {suffix}"
                )
        elif tool_name == TOOL_LOOKUP_FILE_REPUTATION:
            if payload.get("count") == 0:
                gaps.append(
                    f"File reputation lookup {reference} matched no file telemetry "
                    f"record. {suffix}"
                )
            elif not payload.get("reputations"):
                gaps.append(
                    f"File reputation lookup {reference} found no reputation record for the "
                    "matched file hash(es); the hash is unknown to the knowledge base, "
                    "which is not a benign assessment."
                )
        elif tool_name == TOOL_LOOKUP_IOC_REPUTATION:
            if payload.get("found") is False:
                gaps.append(
                    f"IOC reputation lookup {reference} found no record for the indicator; "
                    "the indicator is absent from the knowledge base, which is not a benign "
                    "assessment."
                )
            else:
                records = payload.get("records")
                unknown = [
                    str(record.get("indicator"))
                    for record in records
                    if isinstance(record, dict) and record.get("reputation") == "unknown"
                ] if isinstance(records, list) else []
                if unknown:
                    gaps.append(
                        f"IOC reputation lookup {reference} reports "
                        f"{', '.join(sorted(set(unknown)))} as 'unknown'; no assessment is "
                        "available for it."
                    )
        elif tool_name == TOOL_SEARCH_CTI:
            if payload.get("cti_count") == 0:
                gaps.append(
                    f"Threat knowledge search {reference} matched no CTI record. {suffix}"
                )
            if payload.get("technique_count") == 0:
                gaps.append(
                    f"Threat knowledge search {reference} matched no ATT&CK knowledge "
                    f"entry. {suffix}"
                )
        return gaps
