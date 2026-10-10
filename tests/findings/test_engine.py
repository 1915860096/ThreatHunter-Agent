"""Contract, index and finding-rule tests (T08)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from app.evidence.contracts import EvidenceExtractionResult
from app.findings import (
    EvidenceIndex,
    FindingEngine,
    FindingSeverity,
    FindingSupportLevel,
    FindingType,
    SecurityFinding,
    normalize_indicator,
)
from app.findings.index import is_internal_address
from tests.findings.conftest import (
    BENIGN_HASH,
    MALICIOUS_HASH,
    MALICIOUS_IP,
    UNRELATED_HASH,
    attack_record,
    cti_record,
    dns_record,
    endpoint_record,
    file_event_record,
    file_record,
    network_record,
    payload_for,
    reputation_record,
)


def make_finding(**overrides: object) -> SecurityFinding:
    payload: dict[str, object] = {
        "finding_id": "FIND-000001",
        "incident_id": "INC-000001",
        "finding_type": FindingType.SUSPICIOUS_PROCESS_EXECUTION,
        "title": "Title",
        "description": "Description",
        "severity": FindingSeverity.HIGH,
        "support_level": FindingSupportLevel.STRONG,
        "evidence_ids": ["EV-000001"],
        "rule_id": "RULE-PROC-001",
    }
    payload.update(overrides)
    return SecurityFinding(**payload)  # type: ignore[arg-type]


def types_of(findings: list[SecurityFinding]) -> list[str]:
    return [item.finding_type.value for item in findings]


def find(findings: list[SecurityFinding], finding_type: FindingType) -> SecurityFinding:
    matches = [item for item in findings if item.finding_type is finding_type]
    assert matches, f"no {finding_type.value} finding in {types_of(findings)}"
    return matches[0]


# Contract --------------------------------------------------------------------


def test_finding_accepts_valid_payload() -> None:
    built = make_finding(related_indicators=["powershell.exe"], limitations=["limit"])

    assert built.finding_id == "FIND-000001"
    assert built.is_malicious_grade is False
    assert built.severity_rank == 2


@pytest.mark.parametrize("finding_id", ["FIND1", "IOCF-000001", "", "IVD-000001"])
def test_finding_id_prefix_is_enforced(finding_id: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(finding_id=finding_id)


def test_finding_requires_evidence_and_forbids_extras() -> None:
    with pytest.raises(ValidationError):
        make_finding(evidence_ids=[])

    with pytest.raises(ValidationError):
        make_finding(verdict="malicious")

    with pytest.raises(ValidationError, match="duplicates"):
        make_finding(evidence_ids=["EV-000001", "EV-000001"])


@pytest.mark.parametrize("evidence_id", ["EVD-000001", "TC-000001", "1"])
def test_finding_rejects_foreign_evidence_ids(evidence_id: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(evidence_ids=[evidence_id])


def test_finding_enum_values_and_grading() -> None:
    assert {item.value for item in FindingType} == {
        "suspicious_process_execution",
        "suspicious_file_artifact",
        "suspicious_network_activity",
        "malicious_indicator_match",
        "correlated_attack_pattern",
    }
    assert {item.value for item in FindingSeverity} == {"low", "medium", "high", "critical"}
    assert {item.value for item in FindingSupportLevel} == {"weak", "moderate", "strong"}
    assert make_finding(
        finding_type=FindingType.MALICIOUS_INDICATOR_MATCH,
        severity=FindingSeverity.CRITICAL,
    ).is_malicious_grade
    assert not make_finding(
        finding_type=FindingType.MALICIOUS_INDICATOR_MATCH, severity=FindingSeverity.MEDIUM
    ).is_malicious_grade


def test_finding_json_round_trip() -> None:
    built = make_finding()

    assert SecurityFinding.model_validate(json.loads(built.model_dump_json())) == built


# Evidence index ---------------------------------------------------------------


def test_index_lookups_are_case_insensitive_and_structured(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    index = EvidenceIndex(malicious_extraction)

    assert index.by_record("EPE-999-001")
    assert index.by_host("WS-TEST-01")
    assert index.by_process("PowerShell.EXE")
    assert index.by_hash(MALICIOUS_HASH.upper())
    assert index.by_path("C:\\USERS\\U.TEST\\APPDATA\\LOCAL\\TEMP\\UPDATE.PS1")
    assert index.by_domain("SYNC-UPDATE.EXAMPLE.NET")
    assert index.by_indicator(MALICIOUS_IP)
    assert index.by_record("EPE-999-404") == []


def test_index_separates_telemetry_from_knowledge(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    index = EvidenceIndex(malicious_extraction)
    telemetry = {item.evidence_id for item in index.telemetry()}
    knowledge = {item.evidence_id for item in index.knowledge()}

    assert telemetry and knowledge
    assert telemetry.isdisjoint(knowledge)
    assert index.telemetry("network_connection")
    assert index.telemetry("dns_query")
    assert index.telemetry("ioc_reputation") == []


def test_observed_occurrences_requires_telemetry(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    index = EvidenceIndex(malicious_extraction)

    observed = index.observed_occurrences(MALICIOUS_IP)

    assert observed
    assert all("source-class:telemetry" in item.tags for item in observed)
    assert index.observed_occurrences("198.51.100.23") == []
    assert index.observed_occurrences("sync-update.example.net")


def test_repeated_hits_deduplicate_but_keep_sources(
    make_extraction: Any,
) -> None:
    extraction = make_extraction(
        [
            ("search_network_activity", payload_for("search_network_activity", network_record())),
            ("search_network_activity", payload_for("search_network_activity", network_record())),
        ]
    )
    index = EvidenceIndex(extraction)
    flows = index.telemetry("network_connection")

    assert len(flows) == 1
    assert len(extraction.sources_of(flows[0].evidence_id)) == 2
    assert index.record_ids(flows) == ["NET-999-001"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("203.0.113.47", "203.0.113.47"),
        ("SYNC-Update.Example.NET", "sync-update.example.net"),
        ("  10.0.0.1 ", "10.0.0.1"),
        ("", ""),
    ],
)
def test_normalize_indicator(value: str, expected: str) -> None:
    assert normalize_indicator(value) == expected


@pytest.mark.parametrize(
    ("address", "internal"),
    [
        ("10.40.12.14", True),
        ("172.16.0.9", True),
        ("192.168.5.5", True),
        ("127.0.0.1", True),
        ("203.0.113.47", False),
        ("198.51.100.23", False),
        ("192.0.2.88", False),
        ("not-an-ip", False),
    ],
)
def test_internal_address_semantics(address: str, internal: bool) -> None:
    # RFC 5737 documentation ranges are this benchmark's external destinations,
    # so they must stay "external" even though Python's ipaddress.is_private
    # reports them as private since 3.13.
    assert is_internal_address(address) is internal


# Rule 1: suspicious process execution ----------------------------------------


def test_process_rule_flags_document_spawned_encoded_powershell(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    finding = find(FindingEngine().build(malicious_extraction), FindingType.SUSPICIOUS_PROCESS_EXECUTION)

    assert finding.severity is FindingSeverity.HIGH
    assert finding.support_level is FindingSupportLevel.STRONG
    assert finding.rule_id == "RULE-PROC-001"
    assert "winword.exe" in finding.description
    assert any("decoded content is not available" in item for item in finding.limitations)


def test_plain_script_execution_is_low_severity(make_extraction: Any) -> None:
    plain = endpoint_record(
        event_id="EPE-999-010",
        parent_process_name="explorer.exe",
        command_line="powershell.exe -File C:\\Windows\\Tasks\\inventory.ps1",
    )
    extraction = make_extraction(
        [("search_endpoint_events", payload_for("search_endpoint_events", plain))]
    )

    finding = find(FindingEngine().build(extraction), FindingType.SUSPICIOUS_PROCESS_EXECUTION)

    assert finding.severity is FindingSeverity.LOW
    assert finding.support_level is FindingSupportLevel.WEAK
    assert any("not malicious" in item for item in finding.limitations)


def test_non_interpreter_process_produces_no_process_finding(make_extraction: Any) -> None:
    other = endpoint_record(
        event_id="EPE-999-011", process_name="explorer.exe", parent_process_name="userinit.exe",
        command_line="C:\\Windows\\explorer.exe",
    )
    extraction = make_extraction(
        [("search_endpoint_events", payload_for("search_endpoint_events", other))]
    )

    assert FindingEngine().build(extraction) == []


# Rule 2: suspicious file artifact ---------------------------------------------


def test_file_rule_uses_the_files_own_hash_reputation(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    finding = find(FindingEngine().build(malicious_extraction), FindingType.SUSPICIOUS_FILE_ARTIFACT)

    assert finding.severity is FindingSeverity.HIGH
    assert finding.support_level is FindingSupportLevel.STRONG
    assert finding.rule_id == "RULE-FILE-001"
    assert MALICIOUS_HASH in json.dumps(finding.related_indicators)


def test_file_rule_does_not_borrow_an_unrelated_hash_reputation(
    make_extraction: Any,
) -> None:
    extraction = make_extraction(
        [
            (
                "lookup_file_reputation",
                payload_for(
                    "lookup_file_reputation",
                    file_record(sha256=UNRELATED_HASH),
                    reputation_record(indicator=MALICIOUS_HASH, indicator_type="sha256"),
                ),
            )
        ]
    )

    finding = find(FindingEngine().build(extraction), FindingType.SUSPICIOUS_FILE_ARTIFACT)

    assert finding.severity is FindingSeverity.MEDIUM  # unsigned file in temp path
    assert any("No reputation record is known" in item for item in finding.limitations)
    referenced = {item.evidence_type.value for item in EvidenceIndex(extraction).evidence if item.evidence_id in finding.evidence_ids}
    assert "ioc_reputation" not in referenced


def test_file_rule_reports_missing_hash_without_benign_claim(make_extraction: Any) -> None:
    extraction = make_extraction(
        [
            (
                "lookup_file_reputation",
                payload_for("lookup_file_reputation", file_record(sha256=None)),
            )
        ]
    )

    finding = find(FindingEngine().build(extraction), FindingType.SUSPICIOUS_FILE_ARTIFACT)

    assert any("No SHA256 is recorded" in item for item in finding.limitations)
    assert "benign" not in json.dumps(finding.model_dump(mode="json")).lower()


# Rule 3: suspicious network activity -----------------------------------------


def test_network_rule_flags_external_flow_from_script_interpreter(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    finding = find(FindingEngine().build(malicious_extraction), FindingType.SUSPICIOUS_NETWORK_ACTIVITY)

    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.rule_id == "RULE-NET-001"
    assert MALICIOUS_IP in finding.related_indicators
    assert any("not by itself proof" in item for item in finding.limitations)


def test_network_rule_ignores_internal_traffic(make_extraction: Any) -> None:
    internal = network_record(
        event_id="NET-999-050", dst_ip="10.40.5.31", dst_port=445, direction="outbound"
    )
    extraction = make_extraction(
        [("search_network_activity", payload_for("search_network_activity", internal))]
    )

    assert FindingEngine().build(extraction) == []


# Rule 4: malicious indicator match --------------------------------------------


def test_indicator_rule_requires_an_observed_indicator(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    finding = find(FindingEngine().build(malicious_extraction), FindingType.MALICIOUS_INDICATOR_MATCH)

    assert finding.severity is FindingSeverity.CRITICAL
    assert finding.rule_id == "RULE-IOC-001"
    assert any("reputation record is a knowledge-base assertion" in item for item in finding.limitations)


def test_knowledge_only_malicious_indicator_produces_no_finding(make_extraction: Any) -> None:
    engine = FindingEngine()
    extraction = make_extraction(
        [("lookup_ioc_reputation", payload_for("lookup_ioc_reputation", reputation_record()))]
    )

    findings = engine.build(extraction)

    assert findings == []
    assert engine.skipped_malicious_indicators == [MALICIOUS_IP]


@pytest.mark.parametrize("reputation", ["unknown", "suspicious", "benign"])
def test_non_malicious_reputation_never_creates_an_indicator_finding(
    make_extraction: Any, reputation: str
) -> None:
    extraction = make_extraction(
        [
            ("search_network_activity", payload_for("search_network_activity", network_record())),
            (
                "lookup_ioc_reputation",
                payload_for("lookup_ioc_reputation", reputation_record(reputation=reputation)),
            ),
        ]
    )

    findings = FindingEngine().build(extraction)

    assert FindingType.MALICIOUS_INDICATOR_MATCH not in [
        item.finding_type for item in findings
    ]


def test_cti_and_attack_alone_produce_no_findings(make_extraction: Any) -> None:
    extraction = make_extraction(
        [("search_cti", payload_for("search_cti", cti_record(), attack_record()))]
    )

    assert FindingEngine().build(extraction) == []


# Rule 5: correlated attack pattern --------------------------------------------


def test_correlation_rule_links_dns_answer_to_flow(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    finding = find(FindingEngine().build(malicious_extraction), FindingType.CORRELATED_ATTACK_PATTERN)

    assert finding.severity is FindingSeverity.HIGH  # the destination is malicious
    assert finding.support_level is FindingSupportLevel.STRONG
    assert finding.rule_id == "RULE-CORR-001"
    assert any("knowledge references" in item for item in finding.limitations)
    assert "203.0.113.47" in json.dumps(finding.related_indicators)


def test_correlation_requires_the_same_host_or_process(make_extraction: Any) -> None:
    # The DNS record and the flow belong to different hosts and processes.
    dns = dns_record(host="ws-other-02", process_name="chrome.exe")
    flow = network_record(src_host="ws-test-01", process_name="explorer.exe")
    extraction = make_extraction(
        [("search_network_activity", payload_for("search_network_activity", flow, dns))]
    )

    findings = FindingEngine().build(extraction)

    assert FindingType.CORRELATED_ATTACK_PATTERN not in [
        item.finding_type for item in findings
    ]


def test_correlation_does_not_use_knowledge_as_an_observation(make_extraction: Any) -> None:
    extraction = make_extraction(
        [("search_cti", payload_for("search_cti", cti_record(), attack_record()))]
    )

    assert FindingEngine().build(extraction) == []


def test_correlation_can_link_a_written_file_to_its_record(make_extraction: Any) -> None:
    extraction = make_extraction(
        [
            (
                "search_endpoint_events",
                payload_for("search_endpoint_events", file_event_record()),
            ),
            (
                "lookup_file_reputation",
                payload_for("lookup_file_reputation", file_record(sha256=UNRELATED_HASH)),
            ),
        ]
    )

    finding = find(FindingEngine().build(extraction), FindingType.CORRELATED_ATTACK_PATTERN)

    assert finding.severity is FindingSeverity.MEDIUM
    assert "powershell.exe" in finding.title


# Engine guarantees ------------------------------------------------------------


def test_finding_ids_are_stable_and_ordered(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    first = FindingEngine().build(malicious_extraction)
    second = FindingEngine().build(malicious_extraction)

    assert [item.finding_id for item in first] == [item.finding_id for item in second]
    assert [item.finding_id for item in first] == [
        f"FIND-{index:06d}" for index in range(1, len(first) + 1)
    ]
    assert [item.finding_type.value for item in first] == [
        item.finding_type.value for item in second
    ]


def test_every_finding_references_existing_evidence(
    malicious_extraction: EvidenceExtractionResult,
) -> None:
    known = {item.evidence_id for item in malicious_extraction.evidence}

    findings = FindingEngine().build(malicious_extraction)

    assert findings
    for finding in findings:
        assert set(finding.evidence_ids) <= known
        assert finding.incident_id == malicious_extraction.incident_id
        assert finding.description
        assert finding.title


def test_empty_extraction_produces_no_findings() -> None:
    extraction = EvidenceExtractionResult(incident_id="INC-000001", case_id="CASE-001")

    assert FindingEngine().build(extraction) == []
