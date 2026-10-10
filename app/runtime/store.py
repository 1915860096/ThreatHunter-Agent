"""In-memory persistence for investigation runtime state.

No database, no table: this is the minimal store the runtime needs so a later
stage can inspect a run's state by incident id.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.runtime.contracts import InvestigationRuntimeState


class RuntimeStateNotFoundError(Exception):
    """Raised when no state is stored for an incident id."""


@runtime_checkable
class RuntimeStore(Protocol):
    """Persistence contract for runtime state."""

    def save_state(self, state: InvestigationRuntimeState) -> None:
        """Persist ``state`` under its incident id."""

    def load_state(self, incident_id: str) -> InvestigationRuntimeState:
        """Return the stored state of ``incident_id``."""


class InMemoryRuntimeStore:
    """Process-local store.

    States are deep-copied on save and on load, so neither the runtime nor a
    reader can alias the stored object.
    """

    def __init__(self) -> None:
        self._states: dict[str, InvestigationRuntimeState] = {}

    def save_state(self, state: InvestigationRuntimeState) -> None:
        self._states[state.incident_id] = state.model_copy(deep=True)

    def load_state(self, incident_id: str) -> InvestigationRuntimeState:
        try:
            state = self._states[incident_id]
        except KeyError as exc:
            raise RuntimeStateNotFoundError(
                f"no runtime state stored for incident {incident_id!r}"
            ) from exc
        return state.model_copy(deep=True)

    def list_incidents(self) -> list[str]:
        """Return the stored incident ids, sorted."""
        return sorted(self._states)
