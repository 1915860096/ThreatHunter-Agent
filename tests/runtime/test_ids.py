"""Tests for the deterministic ID generator."""

from __future__ import annotations

import pytest

from app.runtime import SequentialIdGenerator
from app.runtime.ids import IdGenerator
from app.schemas.common import validate_id


def test_sequential_incident_ids() -> None:
    generator = SequentialIdGenerator()

    assert [generator.next_incident_id() for _ in range(3)] == [
        "INC-000001",
        "INC-000002",
        "INC-000003",
    ]


def test_sequential_plan_ids() -> None:
    generator = SequentialIdGenerator()

    assert [generator.next_plan_id() for _ in range(2)] == ["PLAN-000001", "PLAN-000002"]


def test_sequential_step_ids() -> None:
    generator = SequentialIdGenerator()

    assert [generator.next_step_id() for _ in range(3)] == [
        "STEP-000001",
        "STEP-000002",
        "STEP-000003",
    ]


def test_sequential_tool_call_ids() -> None:
    generator = SequentialIdGenerator()

    assert [generator.next_tool_call_id() for _ in range(3)] == [
        "TC-000001",
        "TC-000002",
        "TC-000003",
    ]


def test_families_count_independently() -> None:
    generator = SequentialIdGenerator()

    generator.next_incident_id()
    generator.next_incident_id()
    generator.next_plan_id()
    generator.next_step_id()
    generator.next_tool_call_id()
    generator.next_tool_call_id()

    assert generator.next_incident_id() == "INC-000003"
    assert generator.next_plan_id() == "PLAN-000002"
    assert generator.next_step_id() == "STEP-000002"
    assert generator.next_tool_call_id() == "TC-000003"


def test_generator_is_deterministic_across_instances() -> None:
    first = SequentialIdGenerator()
    second = SequentialIdGenerator()

    assert first.next_incident_id() == second.next_incident_id()
    assert first.next_tool_call_id() == second.next_tool_call_id()


def test_generator_accepts_a_start_offset() -> None:
    generator = SequentialIdGenerator(start=42)

    assert generator.next_incident_id() == "INC-000042"
    assert generator.next_step_id() == "STEP-000042"


@pytest.mark.parametrize("start", [0, -1])
def test_generator_rejects_invalid_start(start: int) -> None:
    with pytest.raises(ValueError, match="start must be >= 1"):
        SequentialIdGenerator(start=start)


def test_generated_ids_satisfy_the_t02_validators() -> None:
    generator = SequentialIdGenerator()

    assert validate_id(generator.next_incident_id(), "INC-", "incident_id")
    assert validate_id(generator.next_plan_id(), "PLAN-", "plan_id")
    assert validate_id(generator.next_step_id(), "STEP-", "step_id")
    assert validate_id(generator.next_tool_call_id(), "TC-", "tool_call_id")


def test_generator_satisfies_the_id_protocol() -> None:
    generator = SequentialIdGenerator()

    assert isinstance(generator, IdGenerator)
    for method in (
        "next_incident_id",
        "next_plan_id",
        "next_step_id",
        "next_tool_call_id",
    ):
        assert callable(getattr(generator, method))


def test_generated_ids_are_six_digit_padded() -> None:
    generator = SequentialIdGenerator(start=1000000)

    assert generator.next_incident_id() == "INC-1000000"


def test_alert_ids_stay_outside_the_generator() -> None:
    generator = SequentialIdGenerator()

    assert not hasattr(generator, "next_alert_id")
    assert validate_id("ALT-001", "ALT-", "alert_id") == "ALT-001"
