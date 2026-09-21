"""Tests for cross-file dataset validation."""

from __future__ import annotations

import ipaddress
import json
import shutil
from collections import Counter
from datetime import timezone
from pathlib import Path

import pytest

from app.benchmark import (
    BenchmarkLoader,
    GroundTruthLoader,
    validate_dataset,
)
from app.benchmark.loader import EXPECTED_CASE_IDS, EXPECTED_VERDICT_DISTRIBUTION
from app.benchmark.schemas import SHA256_PATTERN

# Public addresses that are safe to use in synthetic security data.
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

# Design targets from the benchmark definition (small but realistic corpus).
TELEMETRY_RANGES = {
    "endpoint": (10, 20),
    "network": (8, 15),
    "dns": (5, 15),
    "files": (3, 8),
}


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


def telemetry_counts(loader: BenchmarkLoader, case_id: str) -> dict[str, int]:
    return {
        "endpoint": len(loader.load_endpoint_events(case_id)),
        "network": len(loader.load_network_events(case_id)),
        "dns": len(loader.load_dns_events(case_id)),
        "files": len(loader.load_file_records(case_id)),
    }


def test_shipped_dataset_is_valid() -> None:
    report = validate_dataset()

    assert report.issues == ()
    assert report.ok is True
    assert report.case_ids == EXPECTED_CASE_IDS


def test_verdict_distribution_matches_the_benchmark_definition() -> None:
    truth_loader = GroundTruthLoader()
    counts = Counter(
        truth_loader.load_ground_truth(case_id).expected_verdict.value
        for case_id in EXPECTED_CASE_IDS
    )

    assert dict(counts) == EXPECTED_VERDICT_DISTRIBUTION


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_each_case_matches_the_telemetry_design_targets(
    loader: BenchmarkLoader, case_id: str
) -> None:
    counts = telemetry_counts(loader, case_id)

    for source, (minimum, maximum) in TELEMETRY_RANGES.items():
        assert minimum <= counts[source] <= maximum, f"{case_id} {source}: {counts[source]}"


def test_total_telemetry_volume_is_in_the_expected_band(loader: BenchmarkLoader) -> None:
    total = sum(sum(telemetry_counts(loader, case_id).values()) for case_id in EXPECTED_CASE_IDS)

    assert 250 <= total <= 400


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_ground_truth_references_existing_telemetry(
    loader: BenchmarkLoader, case_id: str
) -> None:
    truth_loader = GroundTruthLoader()
    telemetry_ids = {
        event.event_id for event in loader.load_endpoint_events(case_id)
    } | {
        event.event_id for event in loader.load_network_events(case_id)
    } | {
        event.event_id for event in loader.load_dns_events(case_id)
    } | {
        record.file_id for record in loader.load_file_records(case_id)
    }
    ground_truth = truth_loader.load_ground_truth(case_id)

    assert set(ground_truth.key_evidence) <= telemetry_ids
    assert set(ground_truth.acceptable_evidence) <= telemetry_ids
    assert set(ground_truth.key_evidence).isdisjoint(ground_truth.acceptable_evidence)


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_telemetry_ids_are_unique_within_a_case(loader: BenchmarkLoader, case_id: str) -> None:
    telemetry_ids = [
        event.event_id for event in loader.load_endpoint_events(case_id)
    ] + [
        event.event_id for event in loader.load_network_events(case_id)
    ] + [
        event.event_id for event in loader.load_dns_events(case_id)
    ] + [record.file_id for record in loader.load_file_records(case_id)]

    assert len(telemetry_ids) == len(set(telemetry_ids))


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_all_timestamps_are_timezone_aware_utc(loader: BenchmarkLoader, case_id: str) -> None:
    records = (
        loader.load_endpoint_events(case_id)
        + loader.load_network_events(case_id)
        + loader.load_dns_events(case_id)
        + loader.load_file_records(case_id)
    )
    records.append(loader.load_initial_alert(case_id))

    for record in records:
        assert record.timestamp.tzinfo is timezone.utc


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_all_file_hashes_are_synthetic_sha256_values(
    loader: BenchmarkLoader, case_id: str
) -> None:
    for record in loader.load_file_records(case_id):
        if record.sha256 is not None:
            assert SHA256_PATTERN.fullmatch(record.sha256)


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_public_addresses_use_documentation_ranges(loader: BenchmarkLoader, case_id: str) -> None:
    addresses: list[str] = []
    for event in loader.load_network_events(case_id):
        addresses.extend([event.src_ip, event.dst_ip])
    for event in loader.load_dns_events(case_id):
        addresses.append(event.src_ip)

    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            continue
        assert any(parsed in network for network in DOCUMENTATION_NETWORKS), address


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_all_domains_use_reserved_example_tlds(loader: BenchmarkLoader, case_id: str) -> None:
    queries = {event.query for event in loader.load_dns_events(case_id)}

    assert queries
    for query in queries:
        if query.endswith(".in-addr.arpa"):
            continue
        assert query.endswith((".example.com", ".example.net", ".example.org")), query


def test_knowledge_covers_every_reputation_class(loader: BenchmarkLoader) -> None:
    reputations = {record.reputation.value for record in loader.load_ioc_reputation_records()}

    assert reputations == {"malicious", "suspicious", "benign", "unknown"}


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_expected_techniques_exist_in_attack_knowledge(
    loader: BenchmarkLoader, case_id: str
) -> None:
    knowledge_ids = {record.technique_id for record in loader.load_attack_techniques()}
    ground_truth = GroundTruthLoader().load_ground_truth(case_id)

    for technique in ground_truth.expected_techniques:
        assert technique.technique_id in knowledge_ids


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_expected_iocs_have_telemetry_or_knowledge_support(
    loader: BenchmarkLoader, case_id: str
) -> None:
    known_indicators = {record.indicator for record in loader.load_ioc_reputation_records()}
    telemetry_text = "".join(
        model.model_dump_json()
        for model in (
            loader.load_case_metadata(case_id),
            loader.load_initial_alert(case_id),
            *loader.load_endpoint_events(case_id),
            *loader.load_network_events(case_id),
            *loader.load_dns_events(case_id),
            *loader.load_file_records(case_id),
        )
    )
    ground_truth = GroundTruthLoader().load_ground_truth(case_id)

    for ioc in ground_truth.expected_iocs:
        assert ioc.indicator in known_indicators or ioc.indicator in telemetry_text


def test_case_declared_sources_match_the_shipped_telemetry(dataset_dir: Path) -> None:
    loader = BenchmarkLoader(dataset_dir)

    for case_id in EXPECTED_CASE_IDS:
        metadata = loader.load_case_metadata(case_id)
        counts = telemetry_counts(loader, case_id)
        declared = {source for source in counts if source in metadata.available_sources}

        assert declared == {source for source, count in counts.items() if count > 0}


# Failure injection -----------------------------------------------------------


def test_validation_reports_missing_cases(dataset_dir: Path) -> None:
    shutil.rmtree(dataset_dir / "cases" / "CASE-008")

    report = validate_dataset(dataset_dir)

    assert not report.ok
    assert any("missing cases: CASE-008" in issue for issue in report.issues)


def test_validation_reports_unexpected_cases(dataset_dir: Path) -> None:
    shutil.copytree(dataset_dir / "cases" / "CASE-001", dataset_dir / "cases" / "CASE-009")

    report = validate_dataset(dataset_dir)

    assert any("unexpected cases: CASE-009" in issue for issue in report.issues)


def test_validation_reports_malformed_json(dataset_dir: Path) -> None:
    (dataset_dir / "cases" / "CASE-002" / "telemetry" / "dns_events.json").write_text(
        "[{", encoding="utf-8"
    )

    report = validate_dataset(dataset_dir)

    assert any("malformed JSON" in issue for issue in report.issues)


def test_validation_reports_naive_timestamp(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-003" / "telemetry" / "endpoint_events.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[0]["timestamp"] = "2026-03-09T21:03:10"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("EndpointEvent" in issue for issue in report.issues)


def test_validation_reports_malformed_sha256(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-004" / "telemetry" / "files.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[0]["sha256"] = "abc123"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("sha256" in issue for issue in report.issues)


def test_validation_reports_duplicate_telemetry_ids(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-005" / "telemetry" / "endpoint_events.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[1]["event_id"] = payload[0]["event_id"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("duplicate telemetry IDs" in issue for issue in report.issues)


def test_validation_reports_unknown_ground_truth_evidence(dataset_dir: Path) -> None:
    path = dataset_dir / "ground_truth" / "CASE-006.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["key_evidence"].append("EPE-006-999")
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("unknown telemetry IDs: EPE-006-999" in issue for issue in report.issues)


def test_validation_reports_ground_truth_case_id_mismatch(dataset_dir: Path) -> None:
    path = dataset_dir / "ground_truth" / "CASE-007.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["case_id"] = "CASE-002"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("ground truth declares case_id CASE-002" in issue for issue in report.issues)


def test_validation_reports_metadata_alert_mismatch(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-001" / "initial_alert.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["alert_id"] = "ALT-777"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("does not match the alert id ALT-777" in issue for issue in report.issues)


def test_validation_reports_unsupported_expected_ioc(dataset_dir: Path) -> None:
    path = dataset_dir / "ground_truth" / "CASE-003.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["expected_iocs"].append(
        {"indicator": "unrelated.example.net", "indicator_type": "domain", "reputation": "malicious"}
    )
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("has no telemetry or knowledge support" in issue for issue in report.issues)


def test_validation_reports_unknown_expected_technique(dataset_dir: Path) -> None:
    path = dataset_dir / "ground_truth" / "CASE-002.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["expected_techniques"].append({"technique_id": "T1048", "required": True})
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("T1048" in issue for issue in report.issues)


def test_validation_reports_wrong_verdict_distribution(dataset_dir: Path) -> None:
    path = dataset_dir / "ground_truth" / "CASE-004.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["expected_verdict"] = "benign"
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("verdict distribution" in issue for issue in report.issues)


def test_validation_reports_declared_source_without_records(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-002" / "telemetry" / "dns_events.json"
    path.write_text("[]", encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("source 'dns' is declared but has no records" in issue for issue in report.issues)


def test_validation_reports_undeclared_source_with_records(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-003" / "case_metadata.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["available_sources"] = ["endpoint", "network", "dns"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("has records but is not declared" in issue for issue in report.issues)


def test_validation_reports_missing_ground_truth_file(dataset_dir: Path) -> None:
    (dataset_dir / "ground_truth" / "CASE-005.json").unlink()

    report = validate_dataset(dataset_dir)

    assert any("ground truth for CASE-005 not found" in issue for issue in report.issues)


def test_validation_reports_malformed_knowledge(dataset_dir: Path) -> None:
    (dataset_dir / "knowledge" / "attack_techniques.json").write_text("{", encoding="utf-8")

    report = validate_dataset(dataset_dir)

    assert any("malformed JSON" in issue for issue in report.issues)


def test_validation_reports_missing_dataset_root(tmp_path: Path) -> None:
    report = validate_dataset(tmp_path / "does-not-exist")

    assert report.case_ids == ()
    assert not report.ok
