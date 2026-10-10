"""Deterministic ID generation for the runtime- and planner-owned families.

Ownership (frozen):

* ``ALT-*`` - external ingestion / dataset;
* ``INC-*`` - :class:`~app.runtime.runtime.InvestigationRuntime`;
* ``PLAN-*`` / ``STEP-*`` - the planner;
* ``TC-*`` - the runtime;
* ``TR-*`` - the existing T04 ``ToolExecutor`` (untouched);
* ``EVD-*`` / ``FND-*`` / ``RPT-*`` - later T06+ layers.

This module generates only the four families above and never touches the T02
ID validators.
"""

from __future__ import annotations

from typing import Final, Protocol, runtime_checkable

INCIDENT_ID_PREFIX: Final[str] = "INC"
PLAN_ID_PREFIX: Final[str] = "PLAN"
STEP_ID_PREFIX: Final[str] = "STEP"
TOOL_CALL_ID_PREFIX: Final[str] = "TC"

ID_DIGITS: Final[int] = 6


@runtime_checkable
class IdGenerator(Protocol):
    """Source of deterministic incident / plan / step / tool-call ids."""

    def next_incident_id(self) -> str:
        """Return the next ``INC-*`` id."""

    def next_plan_id(self) -> str:
        """Return the next ``PLAN-*`` id."""

    def next_step_id(self) -> str:
        """Return the next ``STEP-*`` id."""

    def next_tool_call_id(self) -> str:
        """Return the next ``TC-*`` id."""


class SequentialIdGenerator:
    """Deterministic monotonic generator producing ``INC-000001`` style ids.

    Each family counts independently, so ids stay readable and reproducible
    across runs. Two freshly constructed generators start from the same values,
    which keeps tests deterministic.
    """

    def __init__(self, *, start: int = 1) -> None:
        if start < 1:
            raise ValueError("start must be >= 1")
        self._next: dict[str, int] = {
            INCIDENT_ID_PREFIX: start,
            PLAN_ID_PREFIX: start,
            STEP_ID_PREFIX: start,
            TOOL_CALL_ID_PREFIX: start,
        }

    def _take(self, prefix: str) -> str:
        value = self._next[prefix]
        self._next[prefix] = value + 1
        return f"{prefix}-{value:0{ID_DIGITS}d}"

    def next_incident_id(self) -> str:
        return self._take(INCIDENT_ID_PREFIX)

    def next_plan_id(self) -> str:
        return self._take(PLAN_ID_PREFIX)

    def next_step_id(self) -> str:
        return self._take(STEP_ID_PREFIX)

    def next_tool_call_id(self) -> str:
        return self._take(TOOL_CALL_ID_PREFIX)
