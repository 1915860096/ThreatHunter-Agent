"""Deterministic, evidence-grounded finding rules (T08).

Rules only read **structured evidence fields** (never natural-language
summaries) and never call a model. Order of evaluation is fixed:

1. ``RULE-PROC-001`` suspicious process execution
2. ``RULE-FILE-001`` suspicious file artifact
3. ``RULE-NET-001`` suspicious network activity
4. ``RULE-IOC-001`` malicious indicator match (observed indicator + malicious reputation)
5. ``RULE-CORR-001`` correlated attack pattern (>= 2 independent observed facts)

Guarantees:

* a malicious indicator match requires the indicator to be *observed* in case
  telemetry - knowledge-only indicators produce no finding;
* file reputation is joined strictly by hash, network reputation strictly by
  indicator value, so unrelated records are never merged;
* plain script-interpreter execution stays ``low`` severity with ``weak``
  support and an explicit limitation: it is not malicious by itself;
* CTI and ATT&CK records never appear as observation parties of a correlation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from app.evidence.contracts import EvidenceExtractionResult
from app.findings.contracts import (
    FindingSeverity,
    FindingSupportLevel,
    FindingType,
    SecurityFinding,
)
from app.findings.index import EvidenceIndex, is_internal_address, normalize_indicator
from app.schemas.evidence import Evidence, EvidenceType

SCRIPT_INTERPRETERS: Final[frozenset[str]] = frozenset(
    {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"}
)
DOCUMENT_PROCESSES: Final[frozenset[str]] = frozenset(
    {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"}
)
ENCODING_MARKERS: Final[tuple[str, ...]] = (
    "-encodedcommand",
    "-enc ",
    " -enc",
    "frombase64string",
    "downloadstring",
    "downloadfile",
    "invoke-expression",
    "iex ",
    "iex(",
)
HIDDEN_MARKERS: Final[tuple[str, ...]] = (
    "-w hidden",
    "-windowstyle hidden",
    " windowstyle hidden",
)
TEMP_PATH_MARKERS: Final[tuple[str, ...]] = (
    "\\temp\\",
    "\\tmp\\",
    "/tmp/",
    "\\downloads\\",
    "\\appdata\\local\\temp",
    "\\appdata\\roaming\\",
)

RULE_PROCESS: Final[str] = "RULE-PROC-001"
RULE_FILE: Final[str] = "RULE-FILE-001"
RULE_NETWORK: Final[str] = "RULE-NET-001"
RULE_INDICATOR: Final[str] = "RULE-IOC-001"
RULE_CORRELATION: Final[str] = "RULE-CORR-001"

LIMITATION_KNOWLEDGE_IS_NOT_OBSERVATION: Final[str] = (
    "Threat-intelligence and ATT&CK records are knowledge references; they are not "
    "observations of activity in this case."
)
LIMITATION_REPUTATION_IS_ASSERTION: Final[str] = (
    "A reputation record is a knowledge-base assertion about an indicator; it does not by "
    "itself prove that an attack stage occurred."
)


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _folder_of(path: str) -> str:
    lowered = path.casefold()
    return lowered if any(marker in lowered for marker in TEMP_PATH_MARKERS) else ""


@dataclass
class _Draft:
    """One finding under construction (id assigned later)."""

    finding_type: FindingType
    title: str
    description: str
    severity: FindingSeverity
    support_level: FindingSupportLevel
    evidence_ids: list[str]
    rule_id: str
    related_indicators: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    sort_key: tuple[str, ...] = ()


class FindingEngine:
    """Applies the T08 finding rules to one evidence extraction result."""

    def __init__(self) -> None:
        self._skipped_malicious_indicators: list[str] = []

    @property
    def skipped_malicious_indicators(self) -> list[str]:
        """Malicious indicators that had no observed occurrence in this case."""
        return list(self._skipped_malicious_indicators)

    def build(self, extraction: EvidenceExtractionResult) -> list[SecurityFinding]:
        """Return the deterministic findings of ``extraction``."""
        self._skipped_malicious_indicators = []
        index = EvidenceIndex(extraction)
        malicious_indicators = self._malicious_indicators(index)

        drafts: list[_Draft] = []
        drafts.extend(self._process_drafts(index))
        drafts.extend(self._file_drafts(index))
        drafts.extend(self._network_drafts(index))
        drafts.extend(self._indicator_drafts(index, malicious_indicators))
        drafts.extend(self._correlation_drafts(index, malicious_indicators))

        findings: list[SecurityFinding] = []
        for position, draft in enumerate(drafts, start=1):
            evidence_ids = self._existing_ids(index, draft.evidence_ids)
            if not evidence_ids:
                continue
            findings.append(
                SecurityFinding(
                    finding_id=f"FIND-{position:06d}",
                    incident_id=extraction.incident_id,
                    finding_type=draft.finding_type,
                    title=draft.title,
                    description=draft.description,
                    severity=draft.severity,
                    support_level=draft.support_level,
                    evidence_ids=evidence_ids,
                    related_indicators=list(dict.fromkeys(draft.related_indicators)),
                    limitations=list(dict.fromkeys(draft.limitations)),
                    rule_id=draft.rule_id,
                )
            )
        return findings

    # Rules -------------------------------------------------------------------

    def _process_drafts(self, index: EvidenceIndex) -> list[_Draft]:
        drafts: list[_Draft] = []
        groups: dict[tuple[str, str, str], list[Evidence]] = {}
        for item in index.telemetry(EvidenceType.PROCESS_EXECUTION):
            key = (
                _text(index.content_of(item, "host")),
                _text(index.content_of(item, "process_name")),
                _text(index.content_of(item, "parent_process_name")),
            )
            groups.setdefault(key, []).append(item)

        for (host, process, parent), items in sorted(groups.items()):
            process_folded = process.casefold()
            if process_folded not in SCRIPT_INTERPRETERS:
                continue
            command_lines = [
                _text(index.content_of(item, "command_line")).casefold()
                for item in items
            ]
            encoded = any(
                marker in command_line
                for command_line in command_lines
                for marker in ENCODING_MARKERS
            )
            hidden = any(
                marker in command_line
                for command_line in command_lines
                for marker in HIDDEN_MARKERS
            )
            paths = [_text(index.content_of(item, "file_path")) for item in items]
            temp_path = any(_folder_of(path) for path in paths if path)
            document_parent = parent.casefold() in DOCUMENT_PROCESSES

            evidence_ids = [item.evidence_id for item in items]
            limitations: list[str] = []
            details = [f"host {host or 'unknown'}", f"process {process}"]
            if parent:
                details.append(f"parent process {parent}")

            if document_parent or encoded:
                severity = FindingSeverity.HIGH
                reason = (
                    f"a document process ({parent}) started a script interpreter"
                    if document_parent
                    else "the command line uses an encoded or download-style expression"
                )
            elif hidden or temp_path:
                severity = FindingSeverity.MEDIUM
                reason = (
                    "the command line hides the window"
                    if hidden
                    else "the interpreter runs from a temporary or user-writable path"
                )
            else:
                severity = FindingSeverity.LOW
                reason = "the script interpreter was executed"
                limitations.append(
                    "Script-interpreter execution alone is not malicious; no encoded, hidden "
                    "or document-spawned invocation was observed in this step."
                )

            if encoded:
                limitations.append(
                    "The command line is recorded but its decoded content is not available."
                )
            support = (
                FindingSupportLevel.STRONG
                if document_parent and encoded
                else FindingSupportLevel.MODERATE
                if severity is not FindingSeverity.LOW
                else FindingSupportLevel.WEAK
            )
            drafts.append(
                _Draft(
                    finding_type=FindingType.SUSPICIOUS_PROCESS_EXECUTION,
                    title=f"Suspicious process execution: {process} on {host or 'unknown host'}",
                    description=(
                        f"{len(items)} endpoint record(s) show '{reason}' "
                        f"({', '.join(details)})."
                    ),
                    severity=severity,
                    support_level=support,
                    evidence_ids=evidence_ids,
                    rule_id=RULE_PROCESS,
                    related_indicators=[value for value in (process, parent, *paths) if value],
                    limitations=limitations,
                    sort_key=(host, process, parent),
                )
            )
        return drafts

    def _file_drafts(self, index: EvidenceIndex) -> list[_Draft]:
        drafts: list[_Draft] = []
        for record in index.telemetry(EvidenceType.FILE_ACTIVITY):
            if index.record_class(record) != "file_record":
                continue
            host = _text(index.content_of(record, "host"))
            path = _text(index.content_of(record, "path"))
            file_name = _text(index.content_of(record, "file_name"))
            sha256 = _text(index.content_of(record, "sha256"))
            signed = index.content_of(record, "signed")

            reputations = [
                item
                for item in index.by_indicator(sha256)
                if item.evidence_type is EvidenceType.IOC_REPUTATION and sha256
            ] if sha256 else []
            malicious = [item for item in reputations if index.content_of(item, "reputation") == "malicious"]
            suspicious = [
                item for item in reputations if index.content_of(item, "reputation") == "suspicious"
            ]
            related_events = [
                item
                for item in index.by_path(path)
                if index.record_class(item) == "endpoint_event" and path
            ]

            limitations: list[str] = []
            if malicious:
                severity = FindingSeverity.HIGH
                reason = "the file's own SHA256 has a malicious reputation"
            elif suspicious:
                severity = FindingSeverity.MEDIUM
                reason = "the file's own SHA256 has a suspicious reputation"
            elif _folder_of(path) or signed is False:
                severity = FindingSeverity.MEDIUM
                reason = (
                    "the file is unsigned and was written to a user-writable path"
                    if signed is False
                    else "the file was written to a temporary or download path"
                )
            else:
                continue
            if not sha256:
                limitations.append(
                    "No SHA256 is recorded for this file in telemetry, so its reputation "
                    "cannot be checked."
                )
            elif not reputations:
                limitations.append(
                    "No reputation record is known for this file hash (unknown, not benign)."
                )
            limitations.append(LIMITATION_REPUTATION_IS_ASSERTION)

            evidence_ids = [record.evidence_id]
            evidence_ids.extend(item.evidence_id for item in malicious)
            evidence_ids.extend(item.evidence_id for item in suspicious)
            evidence_ids.extend(item.evidence_id for item in related_events)
            drafts.append(
                _Draft(
                    finding_type=FindingType.SUSPICIOUS_FILE_ARTIFACT,
                    title=f"Suspicious file artifact: {file_name or path} on {host or 'unknown host'}",
                    description=(
                        f"File telemetry records '{reason}' for {path or file_name} "
                        f"on host {host or 'unknown'} "
                        f"({len(index.record_ids([record, *related_events]))} distinct record(s))."
                    ),
                    severity=severity,
                    support_level=(
                        FindingSupportLevel.STRONG
                        if malicious and related_events
                        else FindingSupportLevel.MODERATE
                        if malicious or suspicious
                        else FindingSupportLevel.WEAK
                    ),
                    evidence_ids=evidence_ids,
                    rule_id=RULE_FILE,
                    related_indicators=[value for value in (file_name, path, sha256) if value],
                    limitations=limitations,
                    sort_key=(host, path, file_name),
                )
            )
        return drafts

    def _network_drafts(self, index: EvidenceIndex) -> list[_Draft]:
        drafts: list[_Draft] = []
        groups: dict[tuple[str, str, str], list[Evidence]] = {}
        for item in index.telemetry(EvidenceType.NETWORK_CONNECTION):
            destination = _text(index.content_of(item, "dst_ip"))
            if not destination or is_internal_address(destination):
                continue
            key = (
                destination,
                str(index.content_of(item, "dst_port") or ""),
                _text(index.content_of(item, "direction")) or "outbound",
            )
            groups.setdefault(key, []).append(item)

        for (destination, port, direction), items in sorted(groups.items()):
            processes = [
                _text(index.content_of(item, "process_name")) for item in items
            ]
            script_processes = [
                name for name in processes if name.casefold() in SCRIPT_INTERPRETERS
            ]
            dns_answers = [
                item
                for item in index.telemetry(EvidenceType.DNS_QUERY)
                if normalize_indicator(_text(index.content_of(item, "response")))
                == normalize_indicator(destination)
            ]
            severity = (
                FindingSeverity.MEDIUM if script_processes else FindingSeverity.LOW
            )
            reasons = [f"{direction} flow to {destination}:{port}"]
            if script_processes:
                reasons.append(
                    f"issued by a script interpreter ({', '.join(sorted(set(script_processes)))})"
                )
            if dns_answers:
                reasons.append(
                    f"the destination was resolved by {len(dns_answers)} DNS record(s) in this case"
                )
            evidence_ids = [item.evidence_id for item in items]
            evidence_ids.extend(item.evidence_id for item in dns_answers)
            drafts.append(
                _Draft(
                    finding_type=FindingType.SUSPICIOUS_NETWORK_ACTIVITY,
                    title=f"Suspicious network activity: {direction} flow to {destination}:{port}",
                    description=(
                        f"{len(items)} network record(s) show a {direction} flow to the external "
                        f"destination {destination}:{port}; " + "; ".join(reasons[1:]) + "."
                        if len(reasons) > 1
                        else f"{len(items)} network record(s) show a {direction} flow to the "
                        f"external destination {destination}:{port}."
                    ),
                    severity=severity,
                    support_level=(
                        FindingSupportLevel.MODERATE
                        if script_processes or dns_answers
                        else FindingSupportLevel.WEAK
                    ),
                    evidence_ids=evidence_ids,
                    rule_id=RULE_NETWORK,
                    related_indicators=[destination],
                    limitations=[
                        "Outbound connectivity to an external address is not by itself proof "
                        "of malicious communication."
                    ],
                    sort_key=(destination, port, direction),
                )
            )
        return drafts

    def _indicator_drafts(
        self, index: EvidenceIndex, malicious_indicators: dict[str, list[Evidence]]
    ) -> list[_Draft]:
        drafts: list[_Draft] = []
        for indicator, reputations in sorted(malicious_indicators.items()):
            observed = index.observed_occurrences(indicator)
            if not observed:
                continue
            destinations = [
                item
                for item in observed
                if normalize_indicator(_text(index.content_of(item, "dst_ip")))
                == normalize_indicator(indicator)
            ]
            dns_answers = [
                item
                for item in observed
                if normalize_indicator(_text(index.content_of(item, "response")))
                == normalize_indicator(indicator)
            ]
            hashes = [
                item
                for item in observed
                if _text(index.content_of(item, "sha256")).casefold()
                == indicator.casefold()
            ]
            if destinations:
                severity = FindingSeverity.CRITICAL
                basis = "observed as the destination of a network flow in this case"
            elif hashes:
                severity = FindingSeverity.HIGH
                basis = "observed as a file hash recorded in this case"
            elif dns_answers:
                severity = FindingSeverity.HIGH
                basis = "observed as a DNS answer in this case"
            else:
                severity = FindingSeverity.MEDIUM
                basis = "observed in this case telemetry"

            evidence_ids = [item.evidence_id for item in reputations]
            evidence_ids.extend(item.evidence_id for item in observed)
            drafts.append(
                _Draft(
                    finding_type=FindingType.MALICIOUS_INDICATOR_MATCH,
                    title=f"Malicious indicator observed: {indicator}",
                    description=(
                        f"{indicator} has a malicious reputation record and was {basis} "
                        f"({len(index.record_ids(observed))} distinct observation record(s))."
                    ),
                    severity=severity,
                    support_level=FindingSupportLevel.STRONG,
                    evidence_ids=evidence_ids,
                    rule_id=RULE_INDICATOR,
                    related_indicators=[indicator],
                    limitations=[LIMITATION_REPUTATION_IS_ASSERTION],
                    sort_key=(indicator,),
                )
            )
        return drafts

    def _correlation_drafts(
        self, index: EvidenceIndex, malicious_indicators: dict[str, list[Evidence]]
    ) -> list[_Draft]:
        drafts: list[_Draft] = []
        drafts.extend(self._dns_to_flow_drafts(index, malicious_indicators))
        drafts.extend(self._file_write_drafts(index, malicious_indicators))
        return drafts

    def _dns_to_flow_drafts(
        self, index: EvidenceIndex, malicious_indicators: dict[str, list[Evidence]]
    ) -> list[_Draft]:
        drafts: list[_Draft] = []
        flows = index.telemetry(EvidenceType.NETWORK_CONNECTION)
        for dns in index.telemetry(EvidenceType.DNS_QUERY):
            resolved = _text(index.content_of(dns, "response"))
            if not resolved or is_internal_address(resolved):
                continue
            host = _text(index.content_of(dns, "host"))
            process = _text(index.content_of(dns, "process_name"))
            matches = [
                flow
                for flow in flows
                if normalize_indicator(_text(index.content_of(flow, "dst_ip")))
                == normalize_indicator(resolved)
                and (
                    (host and _text(index.content_of(flow, "src_host")) == host)
                    or (
                        process
                        and _text(index.content_of(flow, "process_name")) == process
                    )
                )
            ]
            if not matches:
                continue
            query = _text(index.content_of(dns, "query"))
            evidence_ids = [dns.evidence_id, *(item.evidence_id for item in matches)]
            record_ids = index.record_ids([dns, *matches])
            if len(record_ids) < 2:
                continue
            malicious = self._reputations_for(index, malicious_indicators, resolved)
            evidence_ids.extend(item.evidence_id for item in malicious)
            drafts.append(
                _Draft(
                    finding_type=FindingType.CORRELATED_ATTACK_PATTERN,
                    title=f"Correlated attack pattern: DNS resolution of {query} followed by connection to {resolved}",
                    description=(
                        f"{len(record_ids)} independent observation record(s) link the DNS query "
                        f"'{query}' (resolved to {resolved}) with {len(matches)} network flow(s) "
                        f"to the same address from host {host or 'unknown'}"
                        + (f" and process {process}" if process else "")
                        + (
                            "; the destination also carries a malicious reputation record"
                            if malicious
                            else ""
                        )
                        + ". "
                        + LIMITATION_KNOWLEDGE_IS_NOT_OBSERVATION
                    ),
                    severity=(
                        FindingSeverity.HIGH if malicious else FindingSeverity.MEDIUM
                    ),
                    support_level=FindingSupportLevel.STRONG,
                    evidence_ids=evidence_ids,
                    rule_id=RULE_CORRELATION,
                    related_indicators=[value for value in (query, resolved) if value],
                    limitations=[LIMITATION_KNOWLEDGE_IS_NOT_OBSERVATION],
                    sort_key=(query, resolved),
                )
            )
        return drafts

    def _file_write_drafts(
        self, index: EvidenceIndex, malicious_indicators: dict[str, list[Evidence]]
    ) -> list[_Draft]:
        drafts: list[_Draft] = []
        records = [
            item
            for item in index.telemetry(EvidenceType.FILE_ACTIVITY)
            if index.record_class(item) == "file_record"
        ]
        events = [
            item
            for item in index.telemetry(EvidenceType.FILE_ACTIVITY)
            if index.record_class(item) == "endpoint_event"
        ]
        for record in records:
            path = _text(index.content_of(record, "path"))
            if not path or not _folder_of(path):
                continue
            written = [
                event
                for event in events
                if _text(index.content_of(event, "file_path")).casefold() == path.casefold()
                and _text(index.content_of(event, "process_name")).casefold()
                in SCRIPT_INTERPRETERS
            ]
            if not written:
                continue
            sha256 = _text(index.content_of(record, "sha256"))
            malicious = self._reputations_for(index, malicious_indicators, sha256)
            evidence_ids = [record.evidence_id, *(item.evidence_id for item in written)]
            evidence_ids.extend(item.evidence_id for item in malicious)
            process = _text(index.content_of(written[0], "process_name"))
            drafts.append(
                _Draft(
                    finding_type=FindingType.CORRELATED_ATTACK_PATTERN,
                    title=(
                        f"Correlated attack pattern: {process} wrote "
                        f"{_text(index.content_of(record, 'file_name')) or path}"
                    ),
                    description=(
                        "Endpoint file telemetry shows a script interpreter writing a file in a "
                        f"user-writable path, and the same path has an on-disk file record "
                        f"({len(index.record_ids([record, *written]))} independent record(s))"
                        + (
                            "; the recorded hash also carries a malicious reputation record"
                            if malicious
                            else ""
                        )
                        + ". "
                        + LIMITATION_KNOWLEDGE_IS_NOT_OBSERVATION
                    ),
                    severity=(
                        FindingSeverity.HIGH if malicious else FindingSeverity.MEDIUM
                    ),
                    support_level=FindingSupportLevel.STRONG,
                    evidence_ids=evidence_ids,
                    rule_id=RULE_CORRELATION,
                    related_indicators=[
                        value for value in (path, sha256, process) if value
                    ],
                    limitations=[LIMITATION_KNOWLEDGE_IS_NOT_OBSERVATION],
                    sort_key=(path, sha256),
                )
            )
        return drafts

    # Helpers -----------------------------------------------------------------

    def _malicious_indicators(self, index: EvidenceIndex) -> dict[str, list[Evidence]]:
        found: dict[str, list[Evidence]] = {}
        for item in index.of_type(EvidenceType.IOC_REPUTATION):
            if index.content_of(item, "reputation") != "malicious":
                continue
            indicator = _text(index.content_of(item, "indicator"))
            if not indicator:
                continue
            key = normalize_indicator(indicator)
            found.setdefault(key, []).append(item)
            if not index.observed_occurrences(indicator):
                self._skipped_malicious_indicators.append(indicator)
        return found

    @staticmethod
    def _reputations_for(
        index: EvidenceIndex, malicious_indicators: dict[str, list[Evidence]], value: str
    ) -> list[Evidence]:
        if not value:
            return []
        return malicious_indicators.get(normalize_indicator(value), [])

    @staticmethod
    def _existing_ids(index: EvidenceIndex, evidence_ids: list[str]) -> list[str]:
        known = {item.evidence_id for item in index.evidence}
        ordered: list[str] = []
        for evidence_id in evidence_ids:
            if evidence_id in known and evidence_id not in ordered:
                ordered.append(evidence_id)
        return ordered
