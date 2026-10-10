"""``search_network_activity``: deterministic network and DNS telemetry query."""

from __future__ import annotations

from app.benchmark.loader import BenchmarkLoader
from app.benchmark.schemas import DNSEvent, NetworkEvent
from app.tools.common import (
    apply_limit,
    ip_exact,
    number_exact,
    sort_telemetry,
    text_contains,
    text_exact,
    time_in_range,
)
from app.tools.contracts import NetworkSearchInput, NetworkSearchPayload

TOOL_NAME = "search_network_activity"


def search_network_activity(
    request: NetworkSearchInput, loader: BenchmarkLoader | None = None
) -> NetworkSearchPayload:
    """Query network and/or DNS telemetry of ``request.case_id``.

    The two sources are filtered, sorted and truncated independently, so
    ``limit`` is a per-source limit and each source reports its own
    ``*_truncated`` flag. Filters that do not apply to a source are not
    evaluated for it - a ``dst_port`` filter never empties the DNS result set.
    """
    dataset = loader or BenchmarkLoader()

    network_items: list[NetworkEvent] = []
    network_truncated = False
    if request.include_network:
        network_matches = [
            event
            for event in dataset.load_network_events(request.case_id)
            if _matches_network(event, request)
        ]
        ordered_network = sort_telemetry(network_matches, id_of=lambda event: event.event_id)
        network_items, network_truncated = apply_limit(ordered_network, request.limit)

    dns_items: list[DNSEvent] = []
    dns_truncated = False
    if request.include_dns:
        dns_matches = [
            event
            for event in dataset.load_dns_events(request.case_id)
            if _matches_dns(event, request)
        ]
        ordered_dns = sort_telemetry(dns_matches, id_of=lambda event: event.event_id)
        dns_items, dns_truncated = apply_limit(ordered_dns, request.limit)

    return NetworkSearchPayload(
        case_id=request.case_id,
        network_events=network_items,
        dns_events=dns_items,
        network_count=len(network_items),
        dns_count=len(dns_items),
        network_truncated=network_truncated,
        dns_truncated=dns_truncated,
    )


def _matches_network(event: NetworkEvent, request: NetworkSearchInput) -> bool:
    """Shared filters plus the network-only filters."""
    return (
        text_exact(event.src_host, request.host)
        and ip_exact(event.src_ip, request.src_ip)
        and ip_exact(event.dst_ip, request.dst_ip)
        and number_exact(event.dst_port, request.dst_port)
        and text_exact(event.protocol, request.protocol)
        and text_exact(event.direction, request.direction)
        and text_exact(event.process_name, request.process_name)
        and time_in_range(event.timestamp, request.start_time, request.end_time)
    )


def _matches_dns(event: DNSEvent, request: NetworkSearchInput) -> bool:
    """Shared filters plus the DNS-only filters."""
    return (
        text_exact(event.host, request.host)
        and ip_exact(event.src_ip, request.src_ip)
        and text_exact(event.query, request.domain)
        and text_contains(event.query, request.query_contains)
        and text_exact(event.record_type, request.record_type)
        and text_exact(event.process_name, request.process_name)
        and time_in_range(event.timestamp, request.start_time, request.end_time)
    )
