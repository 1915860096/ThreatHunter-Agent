"""``search_endpoint_events``: deterministic endpoint telemetry query."""

from __future__ import annotations

from app.benchmark.loader import BenchmarkLoader
from app.benchmark.schemas import EndpointEvent
from app.tools.common import (
    apply_limit,
    sha256_exact,
    sort_telemetry,
    text_contains,
    text_exact,
    text_in,
    time_in_range,
)
from app.tools.contracts import EndpointSearchInput, EndpointSearchPayload

TOOL_NAME = "search_endpoint_events"


def search_endpoint_events(
    request: EndpointSearchInput, loader: BenchmarkLoader | None = None
) -> EndpointSearchPayload:
    """Query the endpoint telemetry of ``request.case_id``.

    The complete match set is filtered and sorted deterministically before
    ``limit`` is applied, so ``truncated`` reports whether more matching events
    existed than were returned. Zero matches is a successful empty result, not
    an error.
    """
    dataset = loader or BenchmarkLoader()
    events = dataset.load_endpoint_events(request.case_id)

    matched = [event for event in events if _matches(event, request)]
    ordered = sort_telemetry(matched, id_of=lambda event: event.event_id)
    items, truncated = apply_limit(ordered, request.limit)

    return EndpointSearchPayload(
        case_id=request.case_id,
        items=items,
        count=len(items),
        truncated=truncated,
    )


def _matches(event: EndpointEvent, request: EndpointSearchInput) -> bool:
    """Apply every provided filter (AND); ``event_types`` behaves as OR."""
    return (
        text_in(event.event_type, request.event_types)
        and text_exact(event.host, request.host)
        and text_exact(event.user, request.user)
        and text_exact(event.process_name, request.process_name)
        and text_exact(event.parent_process_name, request.parent_process_name)
        and text_contains(event.command_line, request.command_line_contains)
        and text_exact(event.file_path, request.file_path)
        and sha256_exact(event.sha256, request.sha256)
        and time_in_range(event.timestamp, request.start_time, request.end_time)
    )
