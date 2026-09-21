"""Tests for the ``InvestigationPlan`` and ``InvestigationStep`` contracts."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas import InvestigationPlan, InvestigationStep, InvestigationStepStatus


def step_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "step_id": "STEP-001",
        "order": 1,
        "action": "Collect process tree for ws-042",
        "rationale": "Determine whether powershell.exe spawned children",
        "suggested_tool": "process_tree",
        "status": "pending",
    }
    payload.update(overrides)
    return payload


def plan_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "plan_id": "PLAN-001",
        "incident_id": "INC-001",
        "alert_id": "ALT-001",
        "objective": "Determine whether the encoded PowerShell execution is malicious",
        "steps": [step_payload()],
        "created_at": "2026-09-22T10:00:00Z",
    }
    payload.update(overrides)
    return payload


def test_valid_pending_step_is_accepted() -> None:
    step = InvestigationStep(**step_payload())

    assert step.status is InvestigationStepStatus.PENDING
    assert step.tool_call_ids == []
    assert step.evidence_ids == []
    assert step.started_at is None
    assert step.completed_at is None
    assert step.error is None


@pytest.mark.parametrize("field", ["step_id", "order", "action", "rationale"])
def test_missing_required_step_fields_are_rejected(field: str) -> None:
    payload = step_payload()
    del payload[field]

    with pytest.raises(ValidationError) as exc_info:
        InvestigationStep(**payload)

    assert exc_info.value.errors()[0]["loc"] == (field,)


@pytest.mark.parametrize("step_id", ["ALT-001", "STEP001", ""])
def test_invalid_step_id_prefix_is_rejected(step_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationStep(**step_payload(step_id=step_id))

    assert exc_info.value.errors()[0]["loc"] == ("step_id",)


@pytest.mark.parametrize("order", [0, -1])
def test_step_order_must_be_positive(order: int) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationStep(**step_payload(order=order))

    assert exc_info.value.errors()[0]["loc"] == ("order",)


@pytest.mark.parametrize("field", ["action", "rationale"])
def test_empty_action_or_rationale_is_rejected(field: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationStep(**step_payload(**{field: "   "}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_running_step_without_started_at_is_rejected() -> None:
    with pytest.raises(ValidationError, match="started_at is required"):
        InvestigationStep(**step_payload(status="running"))


def test_running_step_with_started_at_is_accepted() -> None:
    step = InvestigationStep(
        **step_payload(status="running", started_at="2026-09-22T10:00:00Z")
    )

    assert step.status is InvestigationStepStatus.RUNNING


@pytest.mark.parametrize(
    "overrides",
    [
        {"status": "completed"},
        {"status": "completed", "started_at": "2026-09-22T10:00:00Z"},
        {"status": "completed", "completed_at": "2026-09-22T10:05:00Z"},
    ],
)
def test_completed_step_without_both_timestamps_is_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="started_at and completed_at are required"):
        InvestigationStep(**step_payload(**overrides))


def test_completed_step_with_both_timestamps_is_accepted() -> None:
    step = InvestigationStep(
        **step_payload(
            status="completed",
            started_at="2026-09-22T10:00:00Z",
            completed_at="2026-09-22T10:05:00Z",
        )
    )

    assert step.status is InvestigationStepStatus.COMPLETED
    assert step.completed_at is not None


@pytest.mark.parametrize("error", [None, "", "   "])
def test_failed_step_without_error_is_rejected(error: str | None) -> None:
    with pytest.raises(ValidationError, match="error is required"):
        InvestigationStep(**step_payload(status="failed", error=error))


def test_failed_step_with_error_is_accepted() -> None:
    step = InvestigationStep(**step_payload(status="failed", error="tool timeout"))

    assert step.status is InvestigationStepStatus.FAILED
    assert step.error == "tool timeout"


def test_completed_at_earlier_than_started_at_is_rejected() -> None:
    with pytest.raises(ValidationError, match="completed_at must not be earlier"):
        InvestigationStep(
            **step_payload(
                status="completed",
                started_at="2026-09-22T10:05:00Z",
                completed_at="2026-09-22T10:00:00Z",
            )
        )


def test_skipped_step_needs_no_timestamps() -> None:
    step = InvestigationStep(**step_payload(status="skipped"))

    assert step.status is InvestigationStepStatus.SKIPPED


def test_step_tool_call_ids_must_use_tool_call_prefix() -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationStep(**step_payload(tool_call_ids=["TR-001"]))

    assert exc_info.value.errors()[0]["loc"] == ("tool_call_ids",)


def test_step_evidence_ids_must_use_evidence_prefix() -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationStep(**step_payload(evidence_ids=["ALT-001"]))

    assert exc_info.value.errors()[0]["loc"] == ("evidence_ids",)


def test_step_references_accept_valid_ids() -> None:
    step = InvestigationStep(
        **step_payload(tool_call_ids=["TC-001", "TC-002"], evidence_ids=["EV-001"])
    )

    assert step.tool_call_ids == ["TC-001", "TC-002"]
    assert step.evidence_ids == ["EV-001"]


def test_valid_plan_is_accepted() -> None:
    plan = InvestigationPlan(**plan_payload())

    assert plan.plan_id == "PLAN-001"
    assert plan.incident_id == "INC-001"
    assert plan.alert_id == "ALT-001"
    assert len(plan.steps) == 1


def test_plan_with_a_single_step_is_accepted() -> None:
    plan = InvestigationPlan(**plan_payload(steps=[step_payload()]))

    assert [step.step_id for step in plan.steps] == ["STEP-001"]


def test_plan_without_steps_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationPlan(**plan_payload(steps=[]))

    assert exc_info.value.errors()[0]["loc"] == ("steps",)


def test_plan_with_missing_steps_is_rejected() -> None:
    payload = plan_payload()
    payload.pop("steps")

    with pytest.raises(ValidationError) as exc_info:
        InvestigationPlan(**payload)

    assert exc_info.value.errors()[0]["loc"] == ("steps",)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("plan_id", "PLAN001"),
        ("incident_id", "INC001"),
        ("alert_id", "ALT001"),
    ],
)
def test_invalid_plan_id_prefixes_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationPlan(**plan_payload(**{field: value}))

    assert exc_info.value.errors()[0]["loc"] == (field,)


def test_empty_plan_objective_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationPlan(**plan_payload(objective=""))

    assert exc_info.value.errors()[0]["loc"] == ("objective",)


def test_naive_plan_created_at_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationPlan(**plan_payload(created_at="2026-09-22T10:00:00"))

    assert exc_info.value.errors()[0]["loc"] == ("created_at",)


def test_duplicate_step_order_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        InvestigationPlan(
            **plan_payload(
                steps=[
                    step_payload(step_id="STEP-001", order=1),
                    step_payload(step_id="STEP-002", order=1),
                ]
            )
        )


def test_distinct_step_orders_are_accepted() -> None:
    plan = InvestigationPlan(
        **plan_payload(
            steps=[
                step_payload(step_id="STEP-001", order=1),
                step_payload(step_id="STEP-002", order=2, action="Check DNS history"),
            ]
        )
    )

    assert [step.order for step in plan.steps] == [1, 2]


def test_plan_step_lists_are_not_shared_between_instances() -> None:
    first = InvestigationPlan(**plan_payload())
    second = InvestigationPlan(**plan_payload())

    first.steps.append(InvestigationStep(**step_payload(step_id="STEP-002", order=2)))

    assert len(second.steps) == 1


def test_nested_step_validation_errors_propagate() -> None:
    with pytest.raises(ValidationError) as exc_info:
        InvestigationPlan(**plan_payload(steps=[step_payload(status="running")]))

    assert exc_info.value.errors()[0]["loc"] == ("steps", 0)
