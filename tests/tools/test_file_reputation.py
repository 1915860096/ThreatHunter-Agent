"""Tests for ``lookup_file_reputation`` against the shipped T03 dataset."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.benchmark.loader import BenchmarkLoader
from app.schemas.findings import IOCReputation, IOCType
from app.tools import FileReputationInput, lookup_file_reputation

CASE_ID = "CASE-001"

SCRIPT_HASH = "41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc00"
LOADER_HASH = "a2482b1a9165bec658ec357174d4784f8dbaa28a78c967fc50c87c884379f4ab"
SCRIPT_PATH = "C:\\Users\\d.moreau\\AppData\\Local\\Temp\\update.ps1"


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


def test_lookup_by_sha256_enriches_with_reputation(loader: BenchmarkLoader) -> None:
    payload = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, sha256=SCRIPT_HASH), loader
    )

    assert payload.count == 1
    assert payload.files[0].file_id == "FILE-001-001"
    assert payload.files[0].sha256 == SCRIPT_HASH
    assert [record.indicator for record in payload.reputations] == [SCRIPT_HASH]
    assert payload.reputations[0].reputation is IOCReputation.MALICIOUS
    assert payload.reputations[0].indicator_type is IOCType.SHA256
    assert payload.reputations[0].source == "benchmark-ti"


def test_lookup_by_path_and_file_name_is_case_insensitive(loader: BenchmarkLoader) -> None:
    by_path = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, path=SCRIPT_PATH.lower()), loader
    )
    by_name = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, file_name="UPDATE.PS1"), loader
    )

    assert [record.file_id for record in by_path.files] == ["FILE-001-001"]
    assert [record.file_id for record in by_name.files] == ["FILE-001-001"]


def test_host_is_an_additional_filter(loader: BenchmarkLoader) -> None:
    matching = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, file_name="update.ps1", host="WS-FIN-014"), loader
    )
    contradicting = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, file_name="update.ps1", host="ws-other-001"), loader
    )

    assert matching.count == 1
    assert contradicting.count == 0
    assert contradicting.reputations == []


def test_filters_combine_with_and(loader: BenchmarkLoader) -> None:
    payload = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, file_name="update.ps1", sha256=LOADER_HASH), loader
    )

    assert payload.count == 0


def test_multiple_files_can_share_one_query(dataset_dir: Path) -> None:
    path = dataset_dir / "cases" / CASE_ID / "telemetry" / "files.json"
    records = json.loads(path.read_text(encoding="utf-8"))
    second_host_copy = dict(records[0])
    second_host_copy.update(
        {
            "file_id": "FILE-001-006",
            "timestamp": "2026-03-02T09:11:58Z",
            "host": "ws-fin-015",
            "path": "C:\\Users\\other.user\\AppData\\Local\\Temp\\update.ps1",
        }
    )
    records.append(second_host_copy)
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    loader = BenchmarkLoader(dataset_dir)

    payload = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, file_name="update.ps1"), loader
    )
    narrowed = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, file_name="update.ps1", host="ws-fin-015"), loader
    )

    assert [record.file_id for record in payload.files] == ["FILE-001-001", "FILE-001-006"]
    assert payload.count == 2
    assert [record.file_id for record in narrowed.files] == ["FILE-001-006"]
    assert [record.indicator for record in payload.reputations] == [SCRIPT_HASH]


def test_unknown_reputation_is_preserved(loader: BenchmarkLoader) -> None:
    payload = lookup_file_reputation(
        FileReputationInput(case_id="CASE-008", file_name="diag.dll"), loader
    )

    assert payload.count == 1
    assert len(payload.reputations) == 1
    assert payload.reputations[0].reputation is IOCReputation.UNKNOWN


def test_file_without_hash_yields_no_reputation(loader: BenchmarkLoader) -> None:
    payload = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, file_name="Invoice_2026-03.docx"), loader
    )

    assert payload.count == 1
    assert payload.files[0].sha256 is None
    assert payload.reputations == []


def test_zero_matches_is_a_successful_empty_result(loader: BenchmarkLoader) -> None:
    payload = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, file_name="does-not-exist.exe"), loader
    )

    assert payload.files == []
    assert payload.reputations == []
    assert payload.count == 0


def test_reputation_is_not_merged_into_file_records(loader: BenchmarkLoader) -> None:
    payload = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, sha256=SCRIPT_HASH), loader
    )
    file_fields = set(payload.files[0].model_dump())

    assert set(payload.model_dump()) == {"case_id", "files", "reputations", "count"}
    assert file_fields == set(loader.load_file_records(CASE_ID)[0].model_dump())
    assert "reputation" not in file_fields
    assert "confidence" not in file_fields


def test_multiple_reputation_records_are_returned_in_deterministic_order(
    dataset_dir: Path, loader: BenchmarkLoader
) -> None:
    path = dataset_dir / "knowledge" / "ioc_reputation.json"
    records = json.loads(path.read_text(encoding="utf-8"))
    records.extend(
        [
            {
                "indicator": SCRIPT_HASH,
                "indicator_type": "sha256",
                "reputation": "malicious",
                "confidence": 0.7,
                "source": "zeta-feed",
                "tags": ["case-001"],
                "last_seen": "2026-03-02T09:12:04Z",
            },
            {
                "indicator": SCRIPT_HASH,
                "indicator_type": "sha256",
                "reputation": "suspicious",
                "confidence": 0.4,
                "source": "alpha-feed",
                "tags": ["case-001"],
                "last_seen": "2026-03-02T09:12:04Z",
            },
        ]
    )
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    payload = lookup_file_reputation(
        FileReputationInput(case_id=CASE_ID, sha256=SCRIPT_HASH),
        BenchmarkLoader(dataset_dir),
    )

    assert [record.source for record in payload.reputations] == [
        "alpha-feed",
        "benchmark-ti",
        "zeta-feed",
    ]
