"""Tests for the benchmark dataset schemas."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from app.benchmark.schemas import (
    AttackTechniqueRecord,
    CaseGroundTruth,
    CaseMetadata,
    CTIRecord,
    DNSEvent,
    EndpointEvent,
    ExpectedInvestigation,
    FileRecord,
    GroundTruthTechnique,
    IOCReputationRecord,
    NetworkEvent,
)

VALID_SHA256 = "41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc00"


def metadata_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "case_id": "CASE-001",
        "name": "Encoded PowerShell Download & Execute",
        "description": "Office document spawns an encoded PowerShell command.",
        "difficulty": "easy",
        "available_sources": ["endpoint", "network", "dns", "files"],
        "initial_alert_id": "ALT-001",
    }
    payload.update(overrides)
    return payload


def endpoint_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "EPE-001-003",
        "timestamp": "2026-03-02T09:11:52Z",
        "host": "ws-fin-014",
        "user": "d.moreau",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "pid": 6044,
        "parent_process_name": "winword.exe",
        "command_line": "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA",
        "file_path": None,
        "sha256": None,
        "metadata": {"vendor_event_id": 4688},
    }
    payload.update(overrides)
    return payload


def network_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "NET-001-003",
        "timestamp": "2026-03-02T09:12:05Z",
        "src_host": "ws-fin-014",
        "src_ip": "10.40.12.14",
        "src_port": 53021,
        "dst_ip": "203.0.113.47",
        "dst_port": 443,
        "protocol": "tcp",
        "direction": "outbound",
        "bytes_sent": 842,
        "bytes_received": 12640,
        "process_name": "powershell.exe",
        "metadata": {"sensor": "host-fw"},
    }
    payload.update(overrides)
    return payload


def dns_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": "DNS-001-001",
        "timestamp": "2026-03-02T09:11:53Z",
        "host": "ws-fin-014",
        "src_ip": "10.40.12.14",
        "query": "sync-update.example.net",
        "record_type": "A",
        "response": "203.0.113.47",
        "process_name": "powershell.exe",
        "metadata": {"resolver": "10.40.0.53"},
    }
    payload.update(overrides)
    return payload


def file_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "file_id": "FILE-001-001",
        "timestamp": "2026-03-02T09:11:54Z",
        "host": "ws-fin-014",
        "path": "C:\\Users\\d.moreau\\AppData\\Local\\Temp\\update.ps1",
        "file_name": "update.ps1",
        "sha256": VALID_SHA256,
        "size": 4302,
        "signed": False,
        "signer": None,
        "source_url": "https://sync-update.example.net/update.ps1",
        "metadata": {"zone": "internet"},
    }
    payload.update(overrides)
    return payload


def ioc_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "indicator": "sync-update.example.net",
        "indicator_type": "domain",
        "reputation": "malicious",
        "confidence": 0.88,
        "source": "benchmark-ti",
        "tags": ["case-001"],
        "last_seen": "2026-03-02T09:11:53Z",
    }
    payload.update(overrides)
    return payload


def cti_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "cti_id": "CTI-001",
        "title": "Encoded PowerShell loader",
        "summary": "Synthetic report about an encoded PowerShell loader.",
        "indicators": ["sync-update.example.net"],
        "malware_families": ["SyntheticLoader"],
        "campaigns": ["SYNTH-CAMPAIGN-ALPHA"],
        "technique_ids": ["T1059.001", "T1105"],
        "source": "benchmark-ti",
        "published_at": "2026-02-18T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def technique_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "description": "Adversaries may abuse PowerShell commands and scripts.",
        "tactics": ["execution"],
        "keywords": ["powershell"],
    }
    payload.update(overrides)
    return payload


def ground_truth_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "case_id": "CASE-001",
        "expected_verdict": "malicious",
        "expected_iocs": [
            {"indicator": "203.0.113.47", "indicator_type": "ipv4", "reputation": "malicious"}
        ],
        "expected_techniques": [{"technique_id": "T1059.001", "required": True}],
        "key_evidence": ["EPE-001-003", "NET-001-003"],
        "acceptable_evidence": ["DNS-001-001", "FILE-001-001"],
        "expected_investigation": {
            "required_source_types": ["endpoint", "network"],
            "optional_source_types": ["cti"],
        },
    }
    payload.update(overrides)
    return payload


# CaseMetadata ---------------------------------------------------------------


def test_valid_case_metadata_is_accepted() -> None:
    metadata = CaseMetadata(**metadata_payload())

    assert metadata.case_id == "CASE-001"
    assert metadata.available_sources == ["endpoint", "network", "dns", "files"]
    assert metadata.initial_alert_id == "ALT-001"


@pytest.mark.parametrize("case_id", ["CASE1", "case-001", "ALT-001", ""])
def test_case_metadata_rejects_invalid_case_id(case_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseMetadata(**metadata_payload(case_id=case_id))

    assert exc_info.value.errors()[0]["loc"] == ("case_id",)


@pytest.mark.parametrize("initial_alert_id", ["ALT001", "INC-001", ""])
def test_case_metadata_rejects_invalid_alert_id(initial_alert_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseMetadata(**metadata_payload(initial_alert_id=initial_alert_id))

    assert exc_info.value.errors()[0]["loc"] == ("initial_alert_id",)


@pytest.mark.parametrize("field", ["name", "description", "difficulty"])
def test_case_metadata_requires_non_empty_text(field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseMetadata(**metadata_payload(**{field: "  "}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_case_metadata_requires_at_least_one_source() -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseMetadata(**metadata_payload(available_sources=[]))

    assert exc_info.value.errors()[0]["loc"] == ("available_sources",)


def test_case_metadata_rejects_unknown_source() -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseMetadata(**metadata_payload(available_sources=["endpoint", "registry"]))

    assert exc_info.value.errors()[0]["loc"] == ("available_sources", 1)


@pytest.mark.parametrize(
    "leaked_field",
    ["verdict", "expected_verdict", "expected_iocs", "expected_techniques", "key_evidence"],
)
def test_case_metadata_rejects_ground_truth_fields(leaked_field: str) -> None:
    payload = metadata_payload()
    payload[leaked_field] = "leaked"

    with pytest.raises(ValidationError, match="ground truth fields"):
        CaseMetadata(**payload)


def test_case_metadata_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseMetadata(**metadata_payload(analyst_note="extra"))

    assert exc_info.value.errors()[0]["type"] == "extra_forbidden"


# Telemetry records ----------------------------------------------------------


def test_valid_endpoint_event_is_accepted() -> None:
    event = EndpointEvent(**endpoint_payload())

    assert event.event_id == "EPE-001-003"
    assert event.pid == 6044
    assert event.metadata == {"vendor_event_id": 4688}


@pytest.mark.parametrize("event_id", ["NET-001-003", "EPE001-003", ""])
def test_endpoint_event_rejects_invalid_event_id(event_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        EndpointEvent(**endpoint_payload(event_id=event_id))

    assert exc_info.value.errors()[0]["loc"] == ("event_id",)


@pytest.mark.parametrize("pid", [0, -1])
def test_endpoint_event_rejects_non_positive_pid(pid: int) -> None:
    with pytest.raises(ValidationError) as exc_info:
        EndpointEvent(**endpoint_payload(pid=pid))

    assert exc_info.value.errors()[0]["loc"] == ("pid",)


def test_endpoint_event_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError) as exc_info:
        EndpointEvent(**endpoint_payload(timestamp="2026-03-02T09:11:52"))

    assert exc_info.value.errors()[0]["loc"] == ("timestamp",)


def test_endpoint_event_normalises_timestamp_to_utc() -> None:
    event = EndpointEvent(**endpoint_payload(timestamp="2026-03-02T17:11:52+08:00"))

    assert event.timestamp == datetime(2026, 3, 2, 9, 11, 52, tzinfo=timezone.utc)
    assert event.timestamp.tzinfo is timezone.utc


@pytest.mark.parametrize("field", ["host", "event_type"])
def test_endpoint_event_requires_non_empty_fields(field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        EndpointEvent(**endpoint_payload(**{field: ""}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_endpoint_event_metadata_default_is_not_shared() -> None:
    payload = endpoint_payload()
    payload.pop("metadata")

    first = EndpointEvent(**payload)
    second = EndpointEvent(**payload)

    first.metadata["vendor_event_id"] = 4688

    assert second.metadata == {}


def test_valid_network_event_is_accepted() -> None:
    event = NetworkEvent(**network_payload())

    assert event.dst_ip == "203.0.113.47"
    assert event.dst_port == 443
    assert event.bytes_sent == 842


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
@pytest.mark.parametrize("value", ["203.0.113.999", "not-an-ip", "10.40.12"])
def test_network_event_rejects_invalid_ip(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        NetworkEvent(**network_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_network_event_accepts_ipv6() -> None:
    event = NetworkEvent(**network_payload(dst_ip="2001:db8::1"))

    assert event.dst_ip == "2001:db8::1"


@pytest.mark.parametrize("field", ["src_port", "dst_port"])
@pytest.mark.parametrize("value", [0, 65536, -1])
def test_network_event_rejects_out_of_range_port(field: str, value: int) -> None:
    with pytest.raises(ValidationError) as exc_info:
        NetworkEvent(**network_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_network_event_requires_destination_port() -> None:
    payload = network_payload()
    payload.pop("dst_port")

    with pytest.raises(ValidationError) as exc_info:
        NetworkEvent(**payload)

    assert exc_info.value.errors()[0]["loc"] == ("dst_port",)


@pytest.mark.parametrize("field", ["bytes_sent", "bytes_received"])
def test_network_event_rejects_negative_byte_counts(field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        NetworkEvent(**network_payload(**{field: -1}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


@pytest.mark.parametrize("field", ["protocol", "direction"])
def test_network_event_requires_protocol_and_direction(field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        NetworkEvent(**network_payload(**{field: " "}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_valid_dns_event_is_accepted() -> None:
    event = DNSEvent(**dns_payload())

    assert event.query == "sync-update.example.net"
    assert event.response == "203.0.113.47"


def test_dns_event_rejects_invalid_source_ip() -> None:
    with pytest.raises(ValidationError) as exc_info:
        DNSEvent(**dns_payload(src_ip="203.0.113.999"))

    assert exc_info.value.errors()[0]["loc"] == ("src_ip",)


@pytest.mark.parametrize("field", ["host", "query", "record_type"])
def test_dns_event_requires_non_empty_fields(field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        DNSEvent(**dns_payload(**{field: ""}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_dns_event_allows_missing_response() -> None:
    event = DNSEvent(**dns_payload(response=None))

    assert event.response is None


def test_valid_file_record_is_accepted() -> None:
    record = FileRecord(**file_payload())

    assert record.file_id == "FILE-001-001"
    assert record.sha256 == VALID_SHA256
    assert record.size == 4302


@pytest.mark.parametrize(
    "sha256",
    [
        "41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc0",
        "41ED873F46200BD7DE73ED506218A92672AB61E2C63A3F159193EF2D5A5FFC00",
        "not-a-hash",
    ],
)
def test_file_record_rejects_malformed_sha256(sha256: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        FileRecord(**file_payload(sha256=sha256))

    assert exc_info.value.errors()[0]["loc"] == ("sha256",)


def test_file_record_allows_missing_sha256_and_size() -> None:
    record = FileRecord(**file_payload(sha256=None, size=None, signed=None))

    assert record.sha256 is None
    assert record.size is None
    assert record.signed is None


def test_file_record_rejects_negative_size() -> None:
    with pytest.raises(ValidationError) as exc_info:
        FileRecord(**file_payload(size=-1))

    assert exc_info.value.errors()[0]["loc"] == ("size",)


@pytest.mark.parametrize("field", ["host", "path", "file_name"])
def test_file_record_requires_non_empty_fields(field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        FileRecord(**file_payload(**{field: "  "}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


# Shared knowledge -----------------------------------------------------------


def test_valid_ioc_reputation_record_is_accepted() -> None:
    record = IOCReputationRecord(**ioc_payload())

    assert record.indicator == "sync-update.example.net"
    assert record.confidence == 0.88
    assert record.tags == ["case-001"]


@pytest.mark.parametrize("confidence", [-0.01, 1.01])
def test_ioc_reputation_rejects_confidence_outside_unit_interval(confidence: float) -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCReputationRecord(**ioc_payload(confidence=confidence))

    assert exc_info.value.errors()[0]["loc"] == ("confidence",)


@pytest.mark.parametrize(
    ("field", "value"),
    [("indicator_type", "email"), ("reputation", "probably-bad")],
)
def test_ioc_reputation_rejects_unknown_enum_values(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCReputationRecord(**ioc_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_ioc_reputation_rejects_naive_last_seen() -> None:
    with pytest.raises(ValidationError) as exc_info:
        IOCReputationRecord(**ioc_payload(last_seen="2026-03-02T09:11:53"))

    assert exc_info.value.errors()[0]["loc"] == ("last_seen",)


def test_ioc_reputation_tags_default_is_not_shared() -> None:
    payload = ioc_payload()
    payload.pop("tags")

    first = IOCReputationRecord(**payload)
    second = IOCReputationRecord(**payload)

    first.tags.append("case-001")

    assert second.tags == []


def test_valid_cti_record_is_accepted() -> None:
    record = CTIRecord(**cti_payload())

    assert record.cti_id == "CTI-001"
    assert record.technique_ids == ["T1059.001", "T1105"]
    assert record.published_at == datetime(2026, 2, 18, tzinfo=timezone.utc)


@pytest.mark.parametrize("cti_id", ["CTI001", "CASE-001", ""])
def test_cti_record_rejects_invalid_id(cti_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        CTIRecord(**cti_payload(cti_id=cti_id))

    assert exc_info.value.errors()[0]["loc"] == ("cti_id",)


def test_cti_record_rejects_invalid_technique_id() -> None:
    with pytest.raises(ValidationError) as exc_info:
        CTIRecord(**cti_payload(technique_ids=["T1059.001", "T1059.1"]))

    assert exc_info.value.errors()[0]["loc"] == ("technique_ids", 1)


def test_cti_record_rejects_naive_published_at() -> None:
    with pytest.raises(ValidationError) as exc_info:
        CTIRecord(**cti_payload(published_at="2026-02-18T00:00:00"))

    assert exc_info.value.errors()[0]["loc"] == ("published_at",)


def test_cti_record_lists_default_to_empty() -> None:
    payload = cti_payload()
    for field in ("indicators", "malware_families", "campaigns", "technique_ids"):
        payload.pop(field)

    record = CTIRecord(**payload)

    assert record.indicators == []
    assert record.technique_ids == []


def test_valid_attack_technique_record_is_accepted() -> None:
    record = AttackTechniqueRecord(**technique_payload())

    assert record.technique_id == "T1059.001"
    assert record.tactics == ["execution"]


@pytest.mark.parametrize("technique_id", ["T1059", "T1059.001", "T1003"])
def test_attack_technique_accepts_valid_ids(technique_id: str) -> None:
    assert AttackTechniqueRecord(**technique_payload(technique_id=technique_id)).technique_id


@pytest.mark.parametrize("technique_id", ["1059", "T105", "TA0001", "t1059", ""])
def test_attack_technique_rejects_invalid_ids(technique_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        AttackTechniqueRecord(**technique_payload(technique_id=technique_id))

    assert exc_info.value.errors()[0]["loc"] == ("technique_id",)


@pytest.mark.parametrize("field", ["name", "description"])
def test_attack_technique_requires_non_empty_text(field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        AttackTechniqueRecord(**technique_payload(**{field: ""}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


# Ground truth ---------------------------------------------------------------


def test_ground_truth_technique_required_defaults_to_true() -> None:
    assert GroundTruthTechnique(technique_id="T1003").required is True
    assert GroundTruthTechnique(technique_id="T1003", required=False).required is False


def test_expected_investigation_accepts_disjoint_source_types() -> None:
    expected = ExpectedInvestigation(
        required_source_types=["endpoint", "network"],
        optional_source_types=["cti", "attack"],
    )

    assert expected.required_source_types == ["endpoint", "network"]


def test_expected_investigation_rejects_duplicate_source_types() -> None:
    with pytest.raises(ValidationError, match="duplicates"):
        ExpectedInvestigation(required_source_types=["endpoint", "endpoint"])


def test_expected_investigation_rejects_overlapping_source_types() -> None:
    with pytest.raises(ValidationError, match="both required and optional"):
        ExpectedInvestigation(
            required_source_types=["endpoint"], optional_source_types=["endpoint"]
        )


def test_expected_investigation_rejects_unknown_source_type() -> None:
    with pytest.raises(ValidationError) as exc_info:
        ExpectedInvestigation(required_source_types=["registry"])

    assert exc_info.value.errors()[0]["loc"] == ("required_source_types", 0)


def test_valid_ground_truth_is_accepted() -> None:
    truth = CaseGroundTruth(**ground_truth_payload())

    assert truth.case_id == "CASE-001"
    assert truth.expected_verdict.value == "malicious"
    assert truth.key_evidence == ["EPE-001-003", "NET-001-003"]
    assert truth.notes is None


def test_ground_truth_rejects_invalid_case_id() -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseGroundTruth(**ground_truth_payload(case_id="CASE1"))

    assert exc_info.value.errors()[0]["loc"] == ("case_id",)


@pytest.mark.parametrize("evidence_ids", [["EV-001"], ["ALT-001"], ["TC-001"], [""]])
def test_ground_truth_rejects_non_telemetry_evidence_ids(evidence_ids: list[str]) -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseGroundTruth(**ground_truth_payload(key_evidence=evidence_ids))

    assert exc_info.value.errors()[0]["loc"] == ("key_evidence",)


def test_ground_truth_rejects_duplicate_key_evidence() -> None:
    with pytest.raises(ValidationError, match="duplicate"):
        CaseGroundTruth(
            **ground_truth_payload(
                key_evidence=["EPE-001-003", "EPE-001-003"],
                acceptable_evidence=["NET-001-003"],
            )
        )


def test_ground_truth_rejects_key_evidence_overlapping_acceptable_evidence() -> None:
    with pytest.raises(ValidationError, match="must not overlap"):
        CaseGroundTruth(
            **ground_truth_payload(
                key_evidence=["EPE-001-003"],
                acceptable_evidence=["EPE-001-003", "NET-001-003"],
            )
        )


def test_ground_truth_allows_empty_iocs_and_techniques() -> None:
    truth = CaseGroundTruth(
        **ground_truth_payload(
            expected_verdict="inconclusive",
            expected_iocs=[],
            expected_techniques=[],
        )
    )

    assert truth.expected_iocs == []
    assert truth.expected_techniques == []


def test_ground_truth_rejects_unknown_verdict() -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseGroundTruth(**ground_truth_payload(expected_verdict="probably-bad"))

    assert exc_info.value.errors()[0]["loc"] == ("expected_verdict",)


def test_ground_truth_rejects_invalid_expected_ioc_type() -> None:
    with pytest.raises(ValidationError) as exc_info:
        CaseGroundTruth(
            **ground_truth_payload(
                expected_iocs=[{"indicator": "x", "indicator_type": "email", "reputation": "malicious"}]
            )
        )

    assert exc_info.value.errors()[0]["loc"] == ("expected_iocs", 0, "indicator_type")
