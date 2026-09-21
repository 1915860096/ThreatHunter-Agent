"""Tests for the benchmark loaders."""

from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path

import pytest

from app.benchmark import (
    BenchmarkLoader,
    CaseNotFoundError,
    DatasetFormatError,
    GroundTruthLoader,
    MissingGroundTruthError,
)
from app.benchmark.loader import DEFAULT_DATASET_ROOT, EXPECTED_CASE_IDS
from app.benchmark.schemas import (
    AttackTechniqueRecord,
    CaseGroundTruth,
    CaseMetadata,
    CTIRecord,
    DNSEvent,
    EndpointEvent,
    FileRecord,
    IOCReputationRecord,
    NetworkEvent,
)
from app.schemas import SecurityAlert


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


@pytest.fixture
def truth_loader() -> GroundTruthLoader:
    return GroundTruthLoader()


def test_default_dataset_root_points_inside_the_repository() -> None:
    assert DEFAULT_DATASET_ROOT.is_dir()
    assert (DEFAULT_DATASET_ROOT / "cases").is_dir()
    assert (DEFAULT_DATASET_ROOT / "knowledge").is_dir()
    assert (DEFAULT_DATASET_ROOT / "ground_truth").is_dir()


def test_list_cases_returns_the_eight_benchmark_cases(loader: BenchmarkLoader) -> None:
    assert loader.list_cases() == list(EXPECTED_CASE_IDS)


def test_list_cases_is_sorted(loader: BenchmarkLoader) -> None:
    case_ids = loader.list_cases()

    assert case_ids == sorted(case_ids)


def test_load_case_metadata(loader: BenchmarkLoader) -> None:
    metadata = loader.load_case_metadata("CASE-001")

    assert isinstance(metadata, CaseMetadata)
    assert metadata.case_id == "CASE-001"
    assert metadata.name == "Encoded PowerShell Download & Execute"
    assert metadata.initial_alert_id == "ALT-001"


def test_load_initial_alert_reuses_the_t02_alert_schema(loader: BenchmarkLoader) -> None:
    alert = loader.load_initial_alert("CASE-001")

    assert isinstance(alert, SecurityAlert)
    assert alert.alert_id == "ALT-001"
    assert alert.timestamp.tzinfo is timezone.utc
    assert alert.raw["vendor_rule"] == "EDR-PS-0042"


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_every_case_ships_alert_and_all_four_telemetry_sources(
    loader: BenchmarkLoader, case_id: str
) -> None:
    alert = loader.load_initial_alert(case_id)
    endpoint_events = loader.load_endpoint_events(case_id)
    network_events = loader.load_network_events(case_id)
    dns_events = loader.load_dns_events(case_id)
    file_records = loader.load_file_records(case_id)

    assert alert.alert_id.startswith("ALT-")
    assert all(isinstance(event, EndpointEvent) for event in endpoint_events)
    assert all(isinstance(event, NetworkEvent) for event in network_events)
    assert all(isinstance(event, DNSEvent) for event in dns_events)
    assert all(isinstance(record, FileRecord) for record in file_records)
    assert endpoint_events and network_events and dns_events and file_records


def test_load_endpoint_events_parses_expected_values(loader: BenchmarkLoader) -> None:
    events = loader.load_endpoint_events("CASE-001")
    encoded_powershell = next(event for event in events if event.event_id == "EPE-001-003")

    assert encoded_powershell.process_name == "powershell.exe"
    assert encoded_powershell.parent_process_name == "winword.exe"
    assert encoded_powershell.metadata["encoded_command"] is True


def test_load_network_events_parses_expected_values(loader: BenchmarkLoader) -> None:
    events = loader.load_network_events("CASE-001")
    c2_flow = next(event for event in events if event.event_id == "NET-001-003")

    assert c2_flow.dst_ip == "203.0.113.47"
    assert c2_flow.dst_port == 443
    assert c2_flow.direction == "outbound"


def test_load_dns_events_parses_expected_values(loader: BenchmarkLoader) -> None:
    events = loader.load_dns_events("CASE-001")
    suspicious_lookup = next(event for event in events if event.event_id == "DNS-001-001")

    assert suspicious_lookup.query == "sync-update.example.net"
    assert suspicious_lookup.response == "203.0.113.47"


def test_load_file_records_parses_expected_values(loader: BenchmarkLoader) -> None:
    records = loader.load_file_records("CASE-001")
    script = next(record for record in records if record.file_id == "FILE-001-001")

    assert script.file_name == "update.ps1"
    assert script.source_url == "https://sync-update.example.net/update.ps1"
    assert script.metadata["zone"] == "internet"


def test_load_shared_knowledge(loader: BenchmarkLoader) -> None:
    ioc_records = loader.load_ioc_reputation_records()
    cti_records = loader.load_cti_records()
    techniques = loader.load_attack_techniques()

    assert all(isinstance(record, IOCReputationRecord) for record in ioc_records)
    assert all(isinstance(record, CTIRecord) for record in cti_records)
    assert all(isinstance(record, AttackTechniqueRecord) for record in techniques)
    assert ioc_records and cti_records and techniques


def test_knowledge_sources_are_marked_as_synthetic(loader: BenchmarkLoader) -> None:
    sources = {record.source for record in loader.load_cti_records()}
    ioc_sources = {record.source for record in loader.load_ioc_reputation_records()}

    assert sources == {"benchmark-ti"}
    assert ioc_sources <= {
        "benchmark-ti",
        "benchmark-internal-allowlist",
        "benchmark-community-feed",
    }


# Error handling --------------------------------------------------------------


@pytest.mark.parametrize("case_id", ["CASE-999", "case-001", "CASE-1", "CASE-0011", "", "../CASE-001"])
def test_unknown_or_malformed_case_ids_raise(loader: BenchmarkLoader, case_id: str) -> None:
    with pytest.raises(CaseNotFoundError):
        loader.load_case_metadata(case_id)

    with pytest.raises(CaseNotFoundError):
        loader.load_endpoint_events(case_id)


def test_missing_cases_directory_raises(tmp_path: Path) -> None:
    loader = BenchmarkLoader(tmp_path / "empty-dataset")

    with pytest.raises(DatasetFormatError):
        loader.list_cases()


def test_missing_telemetry_file_raises(dataset_dir: Path) -> None:
    (dataset_dir / "cases" / "CASE-002" / "telemetry" / "network_events.json").unlink()
    loader = BenchmarkLoader(dataset_dir)

    with pytest.raises(DatasetFormatError, match="not found"):
        loader.load_network_events("CASE-002")


def test_missing_knowledge_file_raises(dataset_dir: Path) -> None:
    (dataset_dir / "knowledge" / "cti_records.json").unlink()
    loader = BenchmarkLoader(dataset_dir)

    with pytest.raises(DatasetFormatError, match="not found"):
        loader.load_cti_records()


def test_malformed_json_raises(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-003" / "telemetry" / "dns_events.json"
    path.write_text("[{", encoding="utf-8")
    loader = BenchmarkLoader(dataset_dir)

    with pytest.raises(DatasetFormatError, match="malformed JSON"):
        loader.load_dns_events("CASE-003")


def test_schema_invalid_record_raises(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-004" / "telemetry" / "files.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[0]["sha256"] = "not-a-sha256"
    path.write_text(json.dumps(payload), encoding="utf-8")
    loader = BenchmarkLoader(dataset_dir)

    with pytest.raises(DatasetFormatError, match="FileRecord"):
        loader.load_file_records("CASE-004")


def test_non_array_telemetry_file_raises(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / "CASE-005" / "telemetry" / "files.json"
    path.write_text('{"file_id": "FILE-005-001"}', encoding="utf-8")
    loader = BenchmarkLoader(dataset_dir)

    with pytest.raises(DatasetFormatError, match="JSON array"):
        loader.load_file_records("CASE-005")


def test_ground_truth_loader_reads_ground_truth(truth_loader: GroundTruthLoader) -> None:
    assert truth_loader.list_ground_truth_cases() == list(EXPECTED_CASE_IDS)

    truth = truth_loader.load_ground_truth("CASE-001")

    assert isinstance(truth, CaseGroundTruth)
    assert truth.expected_verdict.value == "malicious"


@pytest.mark.parametrize("case_id", EXPECTED_CASE_IDS)
def test_ground_truth_exists_for_every_case(truth_loader: GroundTruthLoader, case_id: str) -> None:
    assert truth_loader.load_ground_truth(case_id).case_id == case_id


def test_missing_ground_truth_raises(dataset_dir: Path) -> None:
    (dataset_dir / "ground_truth" / "CASE-006.json").unlink()
    truth_loader = GroundTruthLoader(dataset_dir)

    with pytest.raises(MissingGroundTruthError):
        truth_loader.load_ground_truth("CASE-006")


def test_missing_ground_truth_directory_raises(tmp_path: Path) -> None:
    truth_loader = GroundTruthLoader(tmp_path / "empty-dataset")

    with pytest.raises(DatasetFormatError):
        truth_loader.list_ground_truth_cases()


# Path handling ---------------------------------------------------------------


def test_loaders_do_not_depend_on_the_working_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)

    loader = BenchmarkLoader()
    truth_loader = GroundTruthLoader()

    assert loader.list_cases() == list(EXPECTED_CASE_IDS)
    assert loader.load_case_metadata("CASE-001").case_id == "CASE-001"
    assert truth_loader.load_ground_truth("CASE-001").case_id == "CASE-001"


def test_loaders_accept_an_explicit_dataset_root(dataset_dir: Path) -> None:
    loader = BenchmarkLoader(dataset_dir)
    truth_loader = GroundTruthLoader(dataset_dir)

    assert loader.dataset_root == dataset_dir
    assert truth_loader.dataset_root == dataset_dir
    assert loader.list_cases() == list(EXPECTED_CASE_IDS)


def test_loader_accepts_a_string_dataset_root(dataset_dir: Path) -> None:
    loader = BenchmarkLoader(str(dataset_dir))

    assert loader.dataset_root == dataset_dir
