"""Append-only trajectory recording with an authoritative sequence.

The trajectory is the machine-readable story of a run. ``sequence`` is the
authoritative ordering (strictly increasing, starting at 1); timestamps are
informational only, because several events may share a timestamp.

``details`` are sanitised before they are stored: sensitive keys are dropped,
nested structures are summarised, long strings are truncated and a complete
``ToolResult`` payload can never be duplicated into the trajectory.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any, Final

from app.runtime.contracts import TrajectoryEvent, TrajectoryEventType

# Key *names* that must never reach the trajectory: secrets, debug output and
# evaluation answers. Matching is pattern-based so the guard stays effective
# without the runtime ever naming an answer field.
SUSPICIOUS_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(secret|token|password|credential|api[_-]?key|private[_-]?key|auth"
    r"|traceback|stack[_-]?trace|truth|verdict|evidence|expected)",
    re.IGNORECASE,
)

# Keys that would carry a raw tool payload into the trajectory.
PAYLOAD_KEY_NAMES: Final[frozenset[str]] = frozenset(
    {"data", "payload", "tool_result_payload"}
)

MAX_DETAIL_STRING_LENGTH: Final[int] = 200


def _sanitize_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) <= MAX_DETAIL_STRING_LENGTH:
            return value
        return value[:MAX_DETAIL_STRING_LENGTH] + "..."
    if isinstance(value, (list, tuple)):
        if all(item is None or isinstance(item, (bool, int, float, str)) for item in value):
            return [_sanitize_value(item) for item in value]
        return {"type": type(value).__name__, "length": len(value)}
    if isinstance(value, Mapping):
        return {"type": "dict", "keys": sorted(str(key) for key in value)}
    return {"type": type(value).__name__}


def sanitize_details(details: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return trajectory-safe details.

    Sensitive, answer-like or payload-carrying keys are dropped, scalars are
    kept (strings truncated), lists of scalars are kept and anything nested is
    replaced by a compact summary.
    """
    if not details:
        return {}

    safe: dict[str, Any] = {}
    for key, value in details.items():
        if not isinstance(key, str):
            continue
        if key.strip().casefold() in PAYLOAD_KEY_NAMES:
            continue
        if SUSPICIOUS_KEY_PATTERN.search(key):
            continue
        safe[key] = _sanitize_value(value)
    return safe


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


class TrajectoryRecorder:
    """Records trajectory events for one incident."""

    def __init__(self, *, incident_id: str, clock: Callable[[], datetime] | None = None) -> None:
        self._incident_id = incident_id
        self._clock = clock or _default_clock
        self._sequence = 0
        self._events: list[TrajectoryEvent] = []

    @property
    def incident_id(self) -> str:
        """Incident this trajectory belongs to."""
        return self._incident_id

    @property
    def events(self) -> list[TrajectoryEvent]:
        """A copy of the recorded events, in sequence order."""
        return list(self._events)

    @property
    def next_sequence(self) -> int:
        """Sequence number the next event will carry."""
        return self._sequence + 1

    def record(
        self,
        event_type: TrajectoryEventType,
        *,
        step_id: str | None = None,
        tool_call_id: str | None = None,
        tool_result_id: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> TrajectoryEvent:
        """Append one event and return it."""
        self._sequence += 1
        event = TrajectoryEvent(
            sequence=self._sequence,
            timestamp=self._clock(),
            event_type=event_type,
            incident_id=self._incident_id,
            step_id=step_id,
            tool_call_id=tool_call_id,
            tool_result_id=tool_result_id,
            details=sanitize_details(details),
        )
        self._events.append(event)
        return event
