"""Tests for ``search_network_activity`` against the shipped T03 dataset."""

from __future__ import annotations

import pytest

from app.benchmark.loader import BenchmarkLoader
from app.tools import NetworkSearchInput, search_network_activity

CASE_ID = "CASE-001"

HTTPS_FLOW_IDS = ["NET-001-003", "NET-001-004", "NET-001-006", "NET-001-009"]
SUSPICIOUS_DNS_ID = "DNS-001-001"
SUSPICIOUS_DOMAIN = "sync-update.example.net"


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


@pytest.fixture
def network_total(loader: BenchmarkLoader) -> int:
    return len(loader.load_network_events(CASE_ID))


@pytest.fixture
def dns_total(loader: BenchmarkLoader) -> int:
    return len(loader.load_dns_events(CASE_ID))


def dns_ids(payload: object) -> list[str]:
    return [event.event_id for event in payload.dns_events]  # type: ignore[attr-defined]


def network_ids(payload: object) -> list[str]:
    return [event.event_id for event in payload.network_events]  # type: ignore[attr-defined]


def test_combined_search_returns_both_sources_sorted(
    loader: BenchmarkLoader, network_total: int, dns_total: int
) -> None:
    payload = search_network_activity(NetworkSearchInput(case_id=CASE_ID), loader)
    expected_network = sorted(
        loader.load_network_events(CASE_ID), key=lambda event: (event.timestamp, event.event_id)
    )
    expected_dns = sorted(
        loader.load_dns_events(CASE_ID), key=lambda event: (event.timestamp, event.event_id)
    )

    assert network_ids(payload) == [event.event_id for event in expected_network]
    assert dns_ids(payload) == [event.event_id for event in expected_dns]
    assert payload.network_count == network_total
    assert payload.dns_count == dns_total


def test_network_only_search(network_total: int, dns_total: int) -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, include_dns=False)
    )

    assert payload.network_count == network_total
    assert payload.dns_events == []
    assert payload.dns_count == 0
    assert payload.dns_truncated is False


def test_dns_only_search(network_total: int, dns_total: int) -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, include_network=False)
    )

    assert payload.dns_count == dns_total
    assert payload.network_events == []
    assert payload.network_count == 0
    assert payload.network_truncated is False


@pytest.mark.parametrize(
    "filters",
    [
        {"host": "ws-fin-014"},
        {"host": "WS-FIN-014"},
        {"src_ip": "10.40.12.14"},
        {"process_name": "powershell.exe"},
    ],
)
def test_shared_filters_apply_to_both_sources(
    loader: BenchmarkLoader, filters: dict[str, str], network_total: int, dns_total: int
) -> None:
    payload = search_network_activity(NetworkSearchInput(case_id=CASE_ID, **filters), loader)
    expected_network = [
        event.event_id
        for event in sorted(
            loader.load_network_events(CASE_ID),
            key=lambda event: (event.timestamp, event.event_id),
        )
        if (event.src_host or "").casefold() == filters.get("host", "").casefold()
        or (event.src_ip or "").casefold() == filters.get("src_ip", "").casefold()
        or (event.process_name or "").casefold() == filters.get("process_name", "").casefold()
    ]
    expected_dns = [
        event.event_id
        for event in sorted(
            loader.load_dns_events(CASE_ID),
            key=lambda event: (event.timestamp, event.event_id),
        )
        if (event.host or "").casefold() == filters.get("host", "").casefold()
        or (event.src_ip or "").casefold() == filters.get("src_ip", "").casefold()
        or (event.process_name or "").casefold() == filters.get("process_name", "").casefold()
    ]

    assert network_ids(payload) == expected_network
    assert dns_ids(payload) == expected_dns
    assert payload.network_count > 0
    assert payload.dns_count > 0


def test_network_only_filter_does_not_filter_dns(network_total: int, dns_total: int) -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, dst_port=443)
    )

    assert network_ids(payload) == HTTPS_FLOW_IDS
    assert payload.dns_count == dns_total
    assert payload.dns_truncated is False
    assert dns_total > 0


def test_dns_only_filter_does_not_filter_network(network_total: int, dns_total: int) -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, domain=SUSPICIOUS_DOMAIN)
    )

    assert dns_ids(payload) == [SUSPICIOUS_DNS_ID]
    assert payload.network_count == network_total
    assert payload.network_truncated is False


def test_domain_filter_is_exact_and_case_insensitive(loader: BenchmarkLoader) -> None:
    matching = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, domain=SUSPICIOUS_DOMAIN.upper(), include_network=False),
        loader,
    )
    partial = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, domain="sync-update", include_network=False),
        loader,
    )

    assert dns_ids(matching) == [SUSPICIOUS_DNS_ID]
    assert partial.dns_count == 0


def test_query_contains_is_a_case_insensitive_substring(loader: BenchmarkLoader) -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, query_contains="UPDATE.EXAMPLE", include_network=False),
        loader,
    )

    assert dns_ids(payload) == [SUSPICIOUS_DNS_ID]


def test_record_type_filter_applies_to_dns_only() -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, record_type="PTR")
    )

    assert payload.dns_count == 0
    assert payload.network_count > 0


def test_network_and_dns_are_sorted_and_deterministic(loader: BenchmarkLoader) -> None:
    request = NetworkSearchInput(case_id=CASE_ID)

    first = search_network_activity(request, loader)
    second = search_network_activity(request, loader)

    assert network_ids(first) == sorted(
        network_ids(first),
        key=lambda event_id: next(
            (event.timestamp, event.event_id)
            for event in first.network_events
            if event.event_id == event_id
        ),
    )
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_limit_is_per_source(network_total: int, dns_total: int) -> None:
    payload = search_network_activity(NetworkSearchInput(case_id=CASE_ID, limit=2))

    assert payload.network_count == 2
    assert payload.dns_count == 2
    assert payload.network_truncated is True
    assert payload.dns_truncated is True
    assert network_total > 2
    assert dns_total > 2


def test_truncation_is_independent_per_source(network_total: int, dns_total: int) -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, limit=dns_total)
    )

    assert payload.network_count == dns_total
    assert payload.network_truncated is True
    assert payload.dns_count == dns_total
    assert payload.dns_truncated is False


def test_network_only_filter_without_matches_keeps_dns_results(dns_total: int) -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, dst_port=9999)
    )

    assert payload.network_count == 0
    assert payload.network_truncated is False
    assert payload.dns_count == dns_total


def test_shared_filter_without_matches_returns_both_sources_empty() -> None:
    payload = search_network_activity(
        NetworkSearchInput(case_id=CASE_ID, host="ws-does-not-exist")
    )

    assert payload.network_count == 0
    assert payload.dns_count == 0
    assert payload.network_truncated is False
    assert payload.dns_truncated is False


def test_inclusive_time_window_applies_to_both_sources() -> None:
    payload = search_network_activity(
        NetworkSearchInput(
            case_id=CASE_ID,
            start_time="2026-03-02T09:12:05Z",
            end_time="2026-03-02T09:12:35Z",
        )
    )

    assert network_ids(payload) == [
        "NET-001-003",
        "NET-001-004",
        "NET-001-005",
        "NET-001-006",
    ]
    assert dns_ids(payload) == ["DNS-001-004", "DNS-001-005"]


def test_network_activity_is_case_insensitive_but_not_substring_for_protocol() -> None:
    exact = search_network_activity(NetworkSearchInput(case_id=CASE_ID, protocol="TCP"))
    partial = search_network_activity(NetworkSearchInput(case_id=CASE_ID, protocol="tc"))

    assert exact.network_count > 0
    assert partial.network_count == 0
