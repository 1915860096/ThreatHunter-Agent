"""Tests for :class:`~app.evidence.extractor.DeterministicEvidenceExtractor`."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.benchmark.schemas import (
    AttackTechniqueRecord,
    CTIRecord,
    DNSEvent,
    EndpointEvent,
    FileRecord,
    IOCReputationRecord,
    NetworkEvent,
)
from app.evidence.extractor import (
    TAG_CASE_LINKED,
    TAG_KNOWLEDGE_REFERENCE,
    TAG_SOURCE_CLASS_KNOWLEDGE,
    TAG_SOURCE_CLASS_TELEMETRY,
    TAG_UNLINKED_KNOWLEDGE,
    TOOL_LOOKUP_FILE_REPUTATION,
    TOOL_LOOKUP_IOC_REPUTATION,
    TOOL_SEARCH_CTI,
    TOOL_SEARCH_ENDPOINT,
    TOOL_SEARCH_NETWORK,
)
from app.runtime.contracts import InvestigationRun
from app.schemas.evidence import EvidenceType
from app.schemas.tools import ToolCall, ToolResult
from tests.conftest import CASE_ID

CASE_INDICATOR = "203.0.113.47"


def endpoint_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event_id": "EPE-999-001",
        "timestamp": "2026-03-02T09:11:52Z",
        "host": "ws-test-01",
        "user": "u.test",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "pid": 4242,
        "parent_process_name": "winword.exe",
        "command_line": "powershell.exe -NoP -EncodedCommand AAAA",
        "file_path": None,
        "sha256": None,
        "metadata": {"vendor_event_id": 4688, "source_ip": "203.0.113.47"},
    }
    record.update(overrides)
    return record


def network_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event_id": "NET-999-001",
        "timestamp": "2026-03-02T09:12:05Z",
        "src_host": "ws-test-01",
        "src_ip": "192.0.2.10",
        "src_port": 53021,
        "dst_ip": "203.0.113.47",
        "dst_port": 443,
        "protocol": "tcp",
        "direction": "outbound",
        "bytes_sent": 100,
        "bytes_received": 200,
        "process_name": "powershell.exe",
        "metadata": {"sensor": "host-fw"},
    }
    record.update(overrides)
    return record


def dns_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event_id": "DNS-999-001",
        "timestamp": "2026-03-02T09:11:53Z",
        "host": "ws-test-01",
        "src_ip": "192.0.2.10",
        "query": "sync-update.example.net",
        "record_type": "A",
        "response": "203.0.113.47",
        "process_name": "powershell.exe",
        "metadata": {"resolver": "192.0.2.53"},
    }
    record.update(overrides)
    return record


def file_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "file_id": "FILE-999-001",
        "timestamp": "2026-03-02T09:11:54Z",
        "host": "ws-test-01",
        "path": "C:\\Users\\u.test\\AppData\\Local\\Temp\\update.ps1",
        "file_name": "update.ps1",
        "sha256": "41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc00",
        "size": 4302,
        "signed": False,
        "signer": None,
        "source_url": "https://sync-update.example.net/update.ps1",
        "metadata": {"zone": "internet"},
    }
    record.update(overrides)
    return record


def reputation_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "indicator": CASE_INDICATOR,
        "indicator_type": "ipv4",
        "reputation": "malicious",
        "confidence": 0.9,
        "source": "benchmark-ti",
        "tags": ["c2"],
        "last_seen": "2026-03-02T09:12:06Z",
    }
    record.update(overrides)
    return record


def cti_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "cti_id": "CTI-999",
        "title": "Synthetic loader report",
        "summary": "Synthetic report summary.",
        "indicators": [CASE_INDICATOR],
        "malware_families": ["SyntheticLoader"],
        "campaigns": ["SYNTH-CAMPAIGN-TEST"],
        "technique_ids": ["T1059.001"],
        "source": "benchmark-ti",
        "published_at": "2026-02-18T00:00:00Z",
    }
    record.update(overrides)
    return record


def attack_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "description": "Adversaries may abuse PowerShell.",
        "tactics": ["execution"],
        "keywords": ["powershell"],
    }
    record.update(overrides)
    return record


def scripted_run(
    run_factory: Any,
    tool_call_factory: Any,
    tool_result_factory: Any,
    tool_name: str,
    payload: Any,
    *,
    index: int = 1,
    success: bool = True,
    error: str | None = None,
    arguments: dict[str, Any] | None = None,
) -> InvestigationRun:
    call = tool_call_factory(tool_name, arguments, index=index)
    result = tool_result_factory(
        call, payload, index=index, success=success, error=error
    )
    return run_factory([(call, result)])


def evidence_by_record(extraction: Any, record_id: str) -> Any:
    matches = [
        item for item in extraction.evidence if item.content.get("record_id") == record_id
    ]
    assert len(matches) == 1, f"expected exactly one evidence for {record_id}"
    return matches[0]


# Endpoint --------------------------------------------------------------------


def test_extracts_endpoint_events(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "case_id": CASE_ID,
        "items": [
            endpoint_record(),
            endpoint_record(
                event_id="EPE-999-002",
                event_type="file_creation",
                process_name="powershell.exe",
            ),
        ],
        "count": 2,
        "truncated": False,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_ENDPOINT, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_count == 2
    process = evidence_by_record(extraction, "EPE-999-001")
    assert process.evidence_type is EvidenceType.PROCESS_EXECUTION
    assert process.reliability == 0.9
    assert process.tags == [
        TAG_SOURCE_CLASS_TELEMETRY,
        f"tool:{TOOL_SEARCH_ENDPOINT}",
    ]
    assert process.provenance.tool_call_id == "TC-000001"
    assert process.provenance.tool_result_id == "TR-0001"
    assert (
        process.provenance.raw_ref
        == "CASE-001/telemetry/endpoint_events.json#EPE-999-001"
    )
    assert process.observed_at is not None
    assert process.observed_at.year == 2026
    assert process.collected_at == run.tool_results[0].returned_at
    assert "source_ip" in process.content
    assert process.content["event_type"] == "process_creation"
    assert "metadata" not in process.content
    assert extraction.sources_of(process.evidence_id)[0].source_fields == sorted(
        key for key in process.content if key != "record_class"
    )


@pytest.mark.parametrize(
    ("event_type", "expected"),
    [
        ("process_creation", EvidenceType.PROCESS_EXECUTION),
        ("process_termination", EvidenceType.PROCESS_EXECUTION),
        ("process_access", EvidenceType.PROCESS_EXECUTION),
        ("file_creation", EvidenceType.FILE_ACTIVITY),
        ("file_modification", EvidenceType.FILE_ACTIVITY),
        ("authentication_failed", EvidenceType.AUTHENTICATION),
        ("authentication_success", EvidenceType.AUTHENTICATION),
        ("registry_write", EvidenceType.OTHER),
    ],
)
def test_endpoint_event_types_map_to_evidence_types(
    extractor: Any,
    run_factory: Any,
    tool_call_factory: Any,
    tool_result_factory: Any,
    event_type: str,
    expected: EvidenceType,
) -> None:
    payload = {
        "case_id": CASE_ID,
        "items": [endpoint_record(event_type=event_type)],
        "count": 1,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_ENDPOINT, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence[0].evidence_type is expected


def test_authentication_metadata_facts_are_kept(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "case_id": CASE_ID,
        "items": [
            endpoint_record(
                event_type="authentication_failed",
                metadata={"logon_type": 10, "source_ip": "203.0.113.77", "status": "0xC000006A"},
            )
        ],
        "count": 1,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_ENDPOINT, payload
    )

    content = extractor.extract(run).evidence[0].content

    assert content["logon_type"] == 10
    assert content["source_ip"] == "203.0.113.77"
    assert content["status"] == "0xC000006A"


# Network and DNS -------------------------------------------------------------


def test_network_and_dns_are_extracted_separately(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "case_id": CASE_ID,
        "network_events": [network_record()],
        "dns_events": [dns_record()],
        "network_count": 1,
        "dns_count": 1,
        "network_truncated": False,
        "dns_truncated": False,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_NETWORK, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_type_counts == {"dns_query": 1, "network_connection": 1}
    flow = evidence_by_record(extraction, "NET-999-001")
    assert flow.evidence_type is EvidenceType.NETWORK_CONNECTION
    assert (
        flow.provenance.raw_ref
        == "CASE-001/telemetry/network_events.json#NET-999-001"
    )
    query = evidence_by_record(extraction, "DNS-999-001")
    assert query.evidence_type is EvidenceType.DNS_QUERY
    assert query.content["query"] == "sync-update.example.net"
    assert query.content["query_type"] == "A"
    assert (
        query.provenance.raw_ref == "CASE-001/telemetry/dns_events.json#DNS-999-001"
    )


def test_dns_without_answer_is_recorded_as_such(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "case_id": CASE_ID,
        "network_events": [],
        "dns_events": [dns_record(response=None)],
        "network_count": 0,
        "dns_count": 1,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_NETWORK, payload
    )

    summary = extractor.extract(run).evidence[0].summary

    assert "no answer recorded" in summary


# File and reputation ---------------------------------------------------------


def test_file_and_reputation_are_extracted_separately(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "case_id": CASE_ID,
        "files": [file_record()],
        "reputations": [reputation_record(indicator="41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc00", indicator_type="sha256", reputation="malicious")],
        "count": 1,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_LOOKUP_FILE_REPUTATION, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_type_counts == {"file_activity": 1, "ioc_reputation": 1}
    file_evidence = evidence_by_record(extraction, "FILE-999-001")
    assert file_evidence.evidence_type is EvidenceType.FILE_ACTIVITY
    assert (
        file_evidence.provenance.raw_ref == "CASE-001/telemetry/files.json#FILE-999-001"
    )
    assert file_evidence.content["file_name"] == "update.ps1"
    assert "reputation" not in file_evidence.content

    reputation = [
        item
        for item in extraction.evidence
        if item.evidence_type is EvidenceType.IOC_REPUTATION
    ][0]
    assert reputation.content["reputation"] == "malicious"
    assert reputation.content["indicator_type"] == "sha256"
    assert (
        reputation.provenance.raw_ref
        == "knowledge/ioc_reputation.json#41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc00|benchmark-ti"
    )


def test_file_without_hash_is_summarised_as_missing_hash(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {"case_id": CASE_ID, "files": [file_record(sha256=None)], "reputations": [], "count": 1}
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_LOOKUP_FILE_REPUTATION, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_count == 1
    assert "no hash recorded" in extraction.evidence[0].summary
    assert "sha256" not in extraction.evidence[0].content


def test_ioc_reputation_tool_extracts_records(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "indicator": CASE_INDICATOR,
        "ioc_type": "ipv4",
        "found": True,
        "records": [reputation_record()],
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_LOOKUP_IOC_REPUTATION, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_count == 1
    item = extraction.evidence[0]
    assert item.evidence_type is EvidenceType.IOC_REPUTATION
    assert item.tags == [
        TAG_SOURCE_CLASS_KNOWLEDGE,
        f"tool:{TOOL_LOOKUP_IOC_REPUTATION}",
        "reputation:malicious",
        TAG_CASE_LINKED,
    ]
    assert "reported 'malicious' by benchmark-ti" in item.summary
    assert "not an observation" not in item.summary


def test_unknown_reputation_is_preserved_as_unknown(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "indicator": "d1f68046f63004fe547db9f0b72f29c82a28de72da70601c909eabda75bf2ede",
        "found": True,
        "records": [
            reputation_record(
                indicator="d1f68046f63004fe547db9f0b72f29c82a28de72da70601c909eabda75bf2ede",
                indicator_type="sha256",
                reputation="unknown",
                confidence=0.0,
            )
        ],
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_LOOKUP_IOC_REPUTATION, payload
    )

    item = extractor.extract(run).evidence[0]

    assert item.content["reputation"] == "unknown"
    assert "no assessment available" in item.summary
    assert "reputation:unknown" in item.tags
    assert "benign" not in json.dumps(item.model_dump(mode="json")).lower()


# CTI and ATT&CK --------------------------------------------------------------


def test_cti_and_attack_are_separated_and_marked_as_references(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "cti_records": [cti_record()],
        "attack_techniques": [attack_record()],
        "cti_count": 1,
        "technique_count": 1,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_CTI, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_type_counts == {
        "attack_knowledge": 1,
        "threat_intelligence": 1,
    }
    cti = evidence_by_record(extraction, "CTI-999")
    assert cti.evidence_type is EvidenceType.THREAT_INTELLIGENCE
    assert TAG_KNOWLEDGE_REFERENCE in cti.tags
    assert TAG_CASE_LINKED in cti.tags
    assert "not confirmed activity" in cti.summary
    assert cti.provenance.raw_ref == "knowledge/cti_records.json#CTI-999"

    technique = evidence_by_record(extraction, "T1059.001")
    assert technique.evidence_type is EvidenceType.ATTACK_KNOWLEDGE
    assert TAG_KNOWLEDGE_REFERENCE in technique.tags
    assert TAG_CASE_LINKED in technique.tags
    assert "not a confirmed technique usage" in technique.summary
    assert technique.provenance.raw_ref == "knowledge/attack_techniques.json#T1059.001"


def test_attack_entries_without_a_case_link_are_marked_unlinked(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "cti_records": [cti_record(indicators=["unrelated.example.net"])],
        "attack_techniques": [
            attack_record(),
            attack_record(technique_id="T1003", name="OS Credential Dumping"),
        ],
        "cti_count": 1,
        "technique_count": 2,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_CTI, payload
    )

    extraction = extractor.extract(run)

    assert TAG_UNLINKED_KNOWLEDGE in evidence_by_record(extraction, "CTI-999").tags
    assert TAG_UNLINKED_KNOWLEDGE in evidence_by_record(extraction, "T1003").tags
    assert TAG_UNLINKED_KNOWLEDGE in evidence_by_record(extraction, "T1059.001").tags
    assert "not linked to a case indicator" in evidence_by_record(
        extraction, "T1003"
    ).summary


def test_case_link_uses_alert_fields_too(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    # 203.0.113.47 is the alert destination of CASE-001.
    payload = {
        "cti_records": [cti_record(indicators=[CASE_INDICATOR])],
        "attack_techniques": [],
        "cti_count": 1,
        "technique_count": 0,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_CTI, payload
    )

    extraction = extractor.extract(run)

    assert TAG_CASE_LINKED in extraction.evidence[0].tags


# Deduplication ---------------------------------------------------------------


def test_repeated_hits_deduplicate_and_keep_every_source(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {"indicator": CASE_INDICATOR, "found": True, "records": [reputation_record()]}
    first_call = tool_call_factory(TOOL_LOOKUP_IOC_REPUTATION, index=1)
    second_call = tool_call_factory(TOOL_LOOKUP_IOC_REPUTATION, index=2)
    run = run_factory(
        [
            (first_call, tool_result_factory(first_call, payload, index=1)),
            (second_call, tool_result_factory(second_call, payload, index=2)),
        ]
    )

    extraction = extractor.extract(run)

    assert extraction.candidate_count == 2
    assert extraction.evidence_count == 1
    assert extraction.duplicate_hit_count == 1
    references = extraction.sources_of("EV-000001")
    assert [(item.tool_call_id, item.tool_result_id) for item in references] == [
        ("TC-000001", "TR-0001"),
        ("TC-000002", "TR-0002"),
    ]
    assert extraction.evidence[0].provenance.tool_call_id == "TC-000001"


def test_different_ioc_sources_are_not_merged(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "indicator": CASE_INDICATOR,
        "found": True,
        "records": [
            reputation_record(source="benchmark-ti"),
            reputation_record(source="benchmark-community-feed", reputation="suspicious", confidence=0.4),
        ],
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_LOOKUP_IOC_REPUTATION, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_count == 2
    assert [
        item.content["source"] for item in extraction.evidence
    ] == ["benchmark-ti", "benchmark-community-feed"]
    assert extraction.sources_of("EV-000001")[0].raw_ref.endswith(
        "#203.0.113.47|benchmark-ti"
    )


# Partial results and warnings ------------------------------------------------


def test_empty_successful_result_produces_no_evidence_and_no_warning(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {"case_id": CASE_ID, "items": [], "count": 0, "truncated": False}
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_ENDPOINT, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence == []
    assert extraction.extraction_warnings == []
    assert extraction.processed_tool_result_ids == ["TR-0001"]


def test_not_found_ioc_produces_no_evidence(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {"indicator": "unknown.example.net", "found": False, "records": []}
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_LOOKUP_IOC_REPUTATION, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence == []
    assert extraction.extraction_warnings == []


def test_failed_tool_result_is_not_extracted(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {"case_id": CASE_ID, "items": [endpoint_record()], "count": 1}
    run = scripted_run(
        run_factory,
        tool_call_factory,
        tool_result_factory,
        TOOL_SEARCH_ENDPOINT,
        payload,
        success=False,
        error="tool 'search_endpoint_events' failed: dataset unavailable",
    )

    extraction = extractor.extract(run)

    assert extraction.evidence == []
    assert extraction.extraction_warnings == []
    assert extraction.processed_tool_result_ids == ["TR-0001"]


def test_malformed_record_adds_warning_and_keeps_valid_records(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {
        "case_id": CASE_ID,
        "items": [
            endpoint_record(),
            {"event_id": "EPE-999-002", "timestamp": "not-a-timestamp", "host": "ws-test-01"},
        ],
        "count": 2,
    }
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_ENDPOINT, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_count == 1
    assert len(extraction.extraction_warnings) == 1
    assert extraction.extraction_warnings[0].startswith("TR-0001: invalid EndpointEvent")
    assert "EPE-999-001" in str(extraction.evidence[0].content)


def test_missing_collection_adds_warning(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {"case_id": CASE_ID, "network_events": [network_record()], "network_count": 1}
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_NETWORK, payload
    )

    extraction = extractor.extract(run)

    assert extraction.evidence_count == 1
    assert any("missing list 'dns_events'" in item for item in extraction.extraction_warnings)


def test_non_object_payload_adds_warning(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    run = scripted_run(
        run_factory,
        tool_call_factory,
        tool_result_factory,
        TOOL_SEARCH_CTI,
        ["not", "an", "object"],
    )

    extraction = extractor.extract(run)

    assert extraction.evidence == []
    assert extraction.extraction_warnings == [
        "TR-0001: unsupported payload for 'search_cti': expected a JSON object, got list"
    ]


def test_unsupported_tool_adds_warning(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, "some_future_tool", {"x": 1}
    )

    extraction = extractor.extract(run)

    assert extraction.evidence == []
    assert "no evidence mapping" in extraction.extraction_warnings[0]


def test_result_without_matching_tool_call_adds_warning(
    extractor: Any, run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    call = tool_call_factory(TOOL_SEARCH_ENDPOINT, index=1)
    orphan_result = tool_result_factory(call, {"items": [], "count": 0}, index=9)
    run = run_factory([(tool_call_factory("search_cti", index=2), tool_result_factory(tool_call_factory("search_cti", index=2), {}, index=2))])
    run = run.model_copy(update={"tool_results": [orphan_result]})

    extraction = extractor.extract(run)

    assert extraction.evidence == []
    assert "no ToolCall found" in extraction.extraction_warnings[0]


# Determinism and provenance integrity ---------------------------------------


def test_extraction_is_repeatable(real_run: InvestigationRun, extractor: Any) -> None:
    first = extractor.extract(real_run)
    second = extractor.extract(real_run)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_identical_runs_produce_identical_evidence(
    case_run_factory: Any,
) -> None:
    from app.evidence import DeterministicEvidenceExtractor

    extractor = DeterministicEvidenceExtractor(case_id=CASE_ID)
    first = extractor.extract(case_run_factory(CASE_ID))
    second = extractor.extract(case_run_factory(CASE_ID))

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_every_reference_points_to_an_existing_tool_result(
    real_run: InvestigationRun, extractor: Any
) -> None:
    extraction = extractor.extract(real_run)
    result_ids = {result.tool_result_id for result in real_run.tool_results}
    call_ids = {call.tool_call_id for call in real_run.tool_calls}

    assert extraction.evidence
    for item in extraction.evidence:
        assert item.provenance.tool_result_id in result_ids
        assert item.provenance.tool_call_id in call_ids
        assert item.evidence_id.startswith("EV-")
        assert item.content
        assert item.incident_id == real_run.incident_id
        for reference in extraction.sources_of(item.evidence_id):
            assert reference.tool_result_id in result_ids
            assert reference.tool_call_id in call_ids
            assert reference.source_fields


def test_real_case_001_extraction_shape(
    real_run: InvestigationRun, extractor: Any
) -> None:
    extraction = extractor.extract(real_run)

    assert extraction.case_id == CASE_ID
    assert extraction.processed_tool_result_ids == [
        result.tool_result_id for result in real_run.tool_results
    ]
    assert extraction.source_reference_count == extraction.candidate_count
    assert extraction.duplicate_hit_count >= 1
    assert extraction.extraction_warnings == []

    dns_evidence = evidence_by_record(extraction, "DNS-001-001")
    assert dns_evidence.provenance.raw_ref == (
        "CASE-001/telemetry/dns_events.json#DNS-001-001"
    )
    assert "sync-update.example.net" in dns_evidence.summary

    unlinked = {
        item.content["record_id"]
        for item in extraction.evidence
        if TAG_UNLINKED_KNOWLEDGE in item.tags
    }
    assert unlinked == {"T1003", "T1071.004", "T1110", "T1218.011"}
    linked = {
        item.content["record_id"]
        for item in extraction.evidence
        if TAG_CASE_LINKED in item.tags
    }
    assert {"CTI-001", "T1059.001", "T1105", "203.0.113.47|benchmark-ti"} <= linked


def test_t02_objects_can_be_rebuilt_from_the_payloads(
    run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> None:
    payload = {"case_id": CASE_ID, "items": [endpoint_record()], "count": 1}
    run = scripted_run(
        run_factory, tool_call_factory, tool_result_factory, TOOL_SEARCH_ENDPOINT, payload
    )

    # The scripted payloads are valid T03 telemetry objects.
    for schema, records in (
        (EndpointEvent, [endpoint_record()]),
        (NetworkEvent, [network_record()]),
        (DNSEvent, [dns_record()]),
        (FileRecord, [file_record()]),
        (IOCReputationRecord, [reputation_record()]),
        (CTIRecord, [cti_record()]),
        (AttackTechniqueRecord, [attack_record()]),
    ):
        for record in records:
            assert schema.model_validate(record)

    assert run.tool_calls[0].tool_name == TOOL_SEARCH_ENDPOINT
