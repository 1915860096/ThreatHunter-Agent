"""Tests for ``search_cti`` (CTI records plus the ATT&CK technique subset)."""

from __future__ import annotations

import pytest

from app.benchmark.loader import BenchmarkLoader
from app.tools import CTISearchInput, search_cti

CTI_INDICATOR = "sync-update.example.net"
STAGING_INDICATOR = "download.example.org"
BEACON_TECHNIQUE = "T1071.004"


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


@pytest.fixture
def technique_total(loader: BenchmarkLoader) -> int:
    return len(loader.load_attack_techniques())


def test_indicator_membership_is_exact(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(indicator=CTI_INDICATOR), loader)

    assert [record.cti_id for record in payload.cti_records] == ["CTI-001"]
    assert payload.cti_count == 1
    assert payload.cti_truncated is False


def test_indicator_lookup_is_case_insensitive(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(indicator=CTI_INDICATOR.upper()), loader)

    assert [record.cti_id for record in payload.cti_records] == ["CTI-001"]


def test_indicator_does_not_match_a_substring(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(indicator="sync-update"), loader)

    assert payload.cti_records == []
    assert payload.cti_count == 0


def test_indicator_filter_does_not_eliminate_attack_results(
    loader: BenchmarkLoader, technique_total: int
) -> None:
    payload = search_cti(CTISearchInput(indicator=CTI_INDICATOR), loader)

    assert payload.cti_count == 1
    assert payload.technique_count == technique_total
    assert payload.technique_count > 0


@pytest.mark.parametrize(
    ("query", "expected_cti_ids"),
    [
        ("second-stage", ["CTI-001"]),
        ("look-alike update domain", ["CTI-001"]),
        ("SyntheticBeacon", ["CTI-003"]),
        ("SYNTH-CAMPAIGN-GAMMA", ["CTI-003"]),
        ("CERTUTIL", ["CTI-004"]),
    ],
)
def test_query_searches_title_summary_families_and_campaigns(
    loader: BenchmarkLoader, query: str, expected_cti_ids: list[str]
) -> None:
    payload = search_cti(CTISearchInput(query=query), loader)

    assert [record.cti_id for record in payload.cti_records] == expected_cti_ids


def test_technique_membership_filter(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(technique_id=BEACON_TECHNIQUE), loader)

    assert [record.cti_id for record in payload.cti_records] == ["CTI-003"]
    assert [record.technique_id for record in payload.attack_techniques] == [BEACON_TECHNIQUE]


def test_technique_filter_searches_attack_by_exact_id(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(technique_id="T1003"), loader)

    assert [record.technique_id for record in payload.attack_techniques] == ["T1003"]
    assert [record.cti_id for record in payload.cti_records] == ["CTI-002"]


@pytest.mark.parametrize(
    ("query", "expected_technique_ids"),
    [
        ("Ingress Tool Transfer", ["T1105"]),
        ("credential material", ["T1003"]),
        ("urlcache", ["T1105"]),
        ("credential-access", ["T1003", "T1110"]),
    ],
)
def test_query_searches_attack_name_description_tactics_and_keywords(
    loader: BenchmarkLoader, query: str, expected_technique_ids: list[str]
) -> None:
    payload = search_cti(CTISearchInput(query=query), loader)

    assert sorted(record.technique_id for record in payload.attack_techniques) == sorted(
        expected_technique_ids
    )


def test_applicable_filters_combine_with_and(loader: BenchmarkLoader) -> None:
    matching = search_cti(CTISearchInput(query="certutil", technique_id="T1105"), loader)
    contradicting = search_cti(CTISearchInput(query="certutil", technique_id="T1003"), loader)

    assert [record.cti_id for record in matching.cti_records] == ["CTI-004"]
    assert contradicting.cti_records == []


def test_collections_are_limited_independently(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(query="download", limit=1), loader)

    assert payload.cti_count == 1
    assert payload.cti_truncated is True
    assert payload.technique_count == 1
    assert payload.technique_truncated is False


def test_zero_results_in_one_collection_is_not_an_error(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(query="execution", limit=1), loader)

    assert payload.cti_records == []
    assert payload.cti_count == 0
    assert payload.cti_truncated is False
    assert payload.technique_count == 1
    assert payload.technique_truncated is True


def test_zero_results_in_both_collections(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(query="not-a-real-threat-keyword"), loader)

    assert payload.cti_records == []
    assert payload.attack_techniques == []
    assert payload.cti_count == 0
    assert payload.technique_count == 0
    assert payload.cti_truncated is False
    assert payload.technique_truncated is False


def test_staging_indicator_selects_the_matching_report(loader: BenchmarkLoader) -> None:
    payload = search_cti(CTISearchInput(indicator=STAGING_INDICATOR), loader)

    assert [record.cti_id for record in payload.cti_records] == ["CTI-004"]


def test_limit_boundary_returns_everything_without_truncation(
    loader: BenchmarkLoader,
) -> None:
    payload = search_cti(CTISearchInput(query="Synthetic report", limit=100), loader)

    assert payload.cti_count == len(loader.load_cti_records())
    assert payload.cti_truncated is False
    assert payload.technique_count == 0


def test_results_are_ordered_and_deterministic(loader: BenchmarkLoader) -> None:
    request = CTISearchInput(query="Synthetic report")

    first = search_cti(request, loader)
    second = search_cti(request, loader)

    assert [record.cti_id for record in first.cti_records] == sorted(
        record.cti_id for record in first.cti_records
    )
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
