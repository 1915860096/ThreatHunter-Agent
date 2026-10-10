"""Tests for ``lookup_ioc_reputation`` against the shipped T03 dataset."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.benchmark.loader import BenchmarkLoader
from app.schemas.findings import IOCReputation, IOCType
from app.tools import IOCReputationInput, lookup_ioc_reputation

MALICIOUS_DOMAIN = "sync-update.example.net"
MALICIOUS_IP = "203.0.113.47"
SUSPICIOUS_IP = "192.0.2.77"
BENIGN_MANAGEMENT_IP = "10.30.8.15"
UNKNOWN_HASH = "d1f68046f63004fe547db9f0b72f29c82a28de72da70601c909eabda75bf2ede"
ABSENT_INDICATOR = "not-known.example.net"


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


@pytest.mark.parametrize(
    ("indicator", "reputation"),
    [
        (MALICIOUS_DOMAIN, IOCReputation.MALICIOUS),
        (SUSPICIOUS_IP, IOCReputation.SUSPICIOUS),
        (BENIGN_MANAGEMENT_IP, IOCReputation.BENIGN),
        (UNKNOWN_HASH, IOCReputation.UNKNOWN),
    ],
)
def test_exact_match_returns_every_reputation_class(
    loader: BenchmarkLoader, indicator: str, reputation: IOCReputation
) -> None:
    payload = lookup_ioc_reputation(IOCReputationInput(indicator=indicator), loader)

    assert payload.found is True
    assert payload.records
    assert payload.records[0].indicator == indicator
    assert payload.records[0].reputation is reputation


def test_lookup_is_case_insensitive_exact(loader: BenchmarkLoader) -> None:
    payload = lookup_ioc_reputation(
        IOCReputationInput(indicator=MALICIOUS_DOMAIN.upper()), loader
    )

    assert payload.found is True
    assert payload.records[0].indicator == MALICIOUS_DOMAIN


def test_lookup_never_matches_a_substring(loader: BenchmarkLoader) -> None:
    prefix = lookup_ioc_reputation(IOCReputationInput(indicator="sync-update"), loader)
    domain_suffix = lookup_ioc_reputation(
        IOCReputationInput(indicator="example.net"), loader
    )

    assert prefix.found is False
    assert prefix.records == []
    assert domain_suffix.found is False


def test_ioc_type_filter_narrows_the_lookup(loader: BenchmarkLoader) -> None:
    matching = lookup_ioc_reputation(
        IOCReputationInput(indicator=MALICIOUS_IP, ioc_type=IOCType.IPV4), loader
    )
    contradicting = lookup_ioc_reputation(
        IOCReputationInput(indicator=MALICIOUS_IP, ioc_type=IOCType.DOMAIN), loader
    )

    assert matching.found is True
    assert matching.records[0].indicator_type is IOCType.IPV4
    assert contradicting.found is False
    assert contradicting.records == []


def test_unknown_reputation_is_not_the_same_as_absent(loader: BenchmarkLoader) -> None:
    unknown = lookup_ioc_reputation(IOCReputationInput(indicator=UNKNOWN_HASH), loader)
    absent = lookup_ioc_reputation(IOCReputationInput(indicator=ABSENT_INDICATOR), loader)

    assert unknown.found is True
    assert unknown.records[0].reputation is IOCReputation.UNKNOWN
    assert absent.found is False
    assert absent.records == []


def test_not_found_returns_an_empty_successful_payload(loader: BenchmarkLoader) -> None:
    payload = lookup_ioc_reputation(IOCReputationInput(indicator="0" * 64), loader)

    assert payload.found is False
    assert payload.records == []
    assert payload.indicator == "0" * 64


def test_lookup_is_deterministic_across_calls(loader: BenchmarkLoader) -> None:
    request = IOCReputationInput(indicator=UNKNOWN_HASH)

    first = lookup_ioc_reputation(request, loader)
    second = lookup_ioc_reputation(request, loader)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_multiple_sources_are_ordered_deterministically(
    dataset_dir: Path, loader: BenchmarkLoader
) -> None:
    path = dataset_dir / "knowledge" / "ioc_reputation.json"
    records = json.loads(path.read_text(encoding="utf-8"))
    for source, reputation in (("zeta-feed", "malicious"), ("alpha-feed", "suspicious")):
        records.append(
            {
                "indicator": SUSPICIOUS_IP,
                "indicator_type": "ipv4",
                "reputation": reputation,
                "confidence": 0.5,
                "source": source,
                "tags": ["case-007"],
                "last_seen": "2026-03-19T03:14:31Z",
            }
        )
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    payload = lookup_ioc_reputation(
        IOCReputationInput(indicator=SUSPICIOUS_IP), BenchmarkLoader(dataset_dir)
    )

    assert payload.found is True
    assert [record.source for record in payload.records] == [
        "alpha-feed",
        "benchmark-ti",
        "zeta-feed",
    ]
