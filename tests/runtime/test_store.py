"""Tests for the in-memory runtime store."""

from __future__ import annotations

import inspect

import pytest

from app.runtime import (
    InMemoryRuntimeStore,
    InvestigationRuntimeState,
    RuntimeStateNotFoundError,
    RuntimeStore,
)
from app.runtime import store as store_module
from tests.runtime.conftest import START_TIME


def state_for(incident_id: str, alert: object) -> InvestigationRuntimeState:
    return InvestigationRuntimeState(
        incident_id=incident_id,
        alert=alert,
        started_at=START_TIME,
        updated_at=START_TIME,
    )


def test_store_saves_and_loads_state(alert: object) -> None:
    store = InMemoryRuntimeStore()
    state = state_for("INC-000001", alert)

    store.save_state(state)
    loaded = store.load_state("INC-000001")

    assert loaded.incident_id == "INC-000001"
    assert loaded.alert.alert_id == state.alert.alert_id
    assert loaded.started_at == START_TIME


def test_store_isolates_saved_state_from_later_mutation(alert: object) -> None:
    store = InMemoryRuntimeStore()
    state = state_for("INC-000001", alert)
    store.save_state(state)

    state.status = "completed"  # type: ignore[assignment]
    state.step_attempts["STEP-000001"] = 3

    loaded = store.load_state("INC-000001")
    assert loaded.status.value == "initialized"
    assert loaded.step_attempts == {}


def test_store_isolates_loaded_state_from_caller_mutation(alert: object) -> None:
    store = InMemoryRuntimeStore()
    store.save_state(state_for("INC-000001", alert))

    first = store.load_state("INC-000001")
    first.total_tool_calls = 7

    assert store.load_state("INC-000001").total_tool_calls == 0


def test_store_raises_for_unknown_incident() -> None:
    store = InMemoryRuntimeStore()

    with pytest.raises(RuntimeStateNotFoundError, match="INC-000404"):
        store.load_state("INC-000404")


def test_store_lists_incidents_sorted(alert: object) -> None:
    store = InMemoryRuntimeStore()
    store.save_state(state_for("INC-000002", alert))
    store.save_state(state_for("INC-000001", alert))

    assert store.list_incidents() == ["INC-000001", "INC-000002"]


def test_store_keeps_incidents_independent(alert: object) -> None:
    store = InMemoryRuntimeStore()
    store.save_state(state_for("INC-000001", alert))
    store.save_state(state_for("INC-000002", alert))

    loaded = store.load_state("INC-000001")
    loaded.step_attempts["STEP-000001"] = 1

    assert store.load_state("INC-000002").step_attempts == {}


def test_in_memory_store_satisfies_the_store_protocol() -> None:
    assert isinstance(InMemoryRuntimeStore(), RuntimeStore)


def test_store_does_not_depend_on_a_database() -> None:
    source = inspect.getsource(store_module).lower()

    assert "sqlalchemy" not in source
    assert "psycopg" not in source
    assert "postgres" not in source
    assert not hasattr(InMemoryRuntimeStore(), "engine")
