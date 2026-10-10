"""Tests for the protocol-conforming deterministic planner."""

from __future__ import annotations

import pytest

from app.agents import PLACEHOLDER_INCIDENT_ID, DeterministicPlanner, InvestigationPlanner
from app.agents.deterministic import (
    TOOL_LOOKUP_FILE_REPUTATION,
    TOOL_LOOKUP_IOC_REPUTATION,
    TOOL_SEARCH_CTI,
    TOOL_SEARCH_ENDPOINT,
    TOOL_SEARCH_NETWORK,
    base_process_name,
    last_file_token,
)
from app.runtime import (
    InvestigationBudget,
    PlannerAction,
    PlanningContext,
    SequentialIdGenerator,
)
from app.schemas.alert import SecurityAlert
from app.schemas.investigation import InvestigationPlan
from app.schemas.tools import ToolCall, ToolResult
from tests.runtime.conftest import CASE_ID, START_TIME, TickingClock, plan_factory, step_factory


def make_planner(case_id: str = CASE_ID, clock: TickingClock | None = None) -> DeterministicPlanner:
    return DeterministicPlanner(
        case_id=case_id,
        id_generator=SequentialIdGenerator(),
        clock=clock or TickingClock(),
    )


def context_with(
    plan: InvestigationPlan,
    step_index: int,
    alert: SecurityAlert,
    *,
    successes: int,
    failures: int = 0,
) -> PlanningContext:
    step = plan.steps[step_index]
    calls: list[ToolCall] = []
    results: list[ToolResult] = []
    for index in range(successes + failures):
        call_id = f"TC-{index + 1:06d}"
        succeeded = index < successes
        calls.append(
            ToolCall(
                tool_call_id=call_id,
                incident_id=plan.incident_id,
                step_id=step.step_id,
                tool_name=TOOL_SEARCH_ENDPOINT,
                status="succeeded" if succeeded else "failed",
                requested_at=START_TIME,
            )
        )
        results.append(
            ToolResult(
                tool_result_id=f"TR-{index + 1:04d}",
                tool_call_id=call_id,
                tool_name=TOOL_SEARCH_ENDPOINT,
                success=succeeded,
                data={} if succeeded else None,
                error=None if succeeded else "tool 'x' failed: boom",
                latency_ms=1,
                returned_at=START_TIME,
            )
        )
    return PlanningContext(
        alert=alert,
        plan=plan,
        current_step=step,
        previous_tool_calls=calls,
        previous_tool_results=results,
        remaining_tool_budget=InvestigationBudget().max_tool_calls - len(calls),
        remaining_step_budget=InvestigationBudget().max_tool_calls_per_step - len(calls),
    )


def test_planner_satisfies_the_protocol() -> None:
    assert isinstance(make_planner(), InvestigationPlanner)


def test_plan_is_created_from_the_alert(alert: SecurityAlert) -> None:
    plan = make_planner().create_plan(alert)

    assert plan.plan_id == "PLAN-000001"
    assert plan.alert_id == alert.alert_id
    assert plan.incident_id == PLACEHOLDER_INCIDENT_ID
    assert plan.objective
    assert [step.order for step in plan.steps] == [1, 2, 3, 4, 5]
    assert [step.step_id for step in plan.steps] == [f"STEP-{index:06d}" for index in range(1, 6)]


def test_plan_stays_valid_for_the_t02_contract(alert: SecurityAlert) -> None:
    plan = make_planner().create_plan(alert)

    revalidated = InvestigationPlan.model_validate(plan.model_dump())

    assert revalidated == plan
    assert all(step.status.value == "pending" for step in plan.steps)


def test_plan_covers_endpoint_network_indicator_and_knowledge_steps(
    alert: SecurityAlert,
) -> None:
    planner = make_planner()
    plan = planner.create_plan(alert)

    tools_per_step = [
        _planned_tools(planner, plan, index, alert) for index in range(len(plan.steps))
    ]

    assert tools_per_step[0] == [TOOL_SEARCH_ENDPOINT, TOOL_SEARCH_ENDPOINT]
    assert tools_per_step[1] == [TOOL_LOOKUP_FILE_REPUTATION]
    assert tools_per_step[2] == [TOOL_SEARCH_NETWORK, TOOL_SEARCH_NETWORK]
    assert tools_per_step[3] == [TOOL_LOOKUP_IOC_REPUTATION, TOOL_LOOKUP_IOC_REPUTATION]
    assert tools_per_step[4] == [TOOL_SEARCH_CTI, TOOL_SEARCH_CTI]


def _planned_tools(
    planner: DeterministicPlanner, plan: InvestigationPlan, step_index: int, alert: SecurityAlert
) -> list[str]:
    """Collect the tool names the planner intends for one step."""
    step = plan.steps[step_index]
    tools: list[str] = []
    for successes in range(0, 6):
        context = context_with(plan, step_index, alert, successes=successes)
        decision = planner.decide_next_action(context)
        if decision.action is PlannerAction.COMPLETE_STEP:
            break
        tools.append(decision.tool_name or "")
    return tools


def test_step_arguments_use_the_alert_and_the_case_id(alert: SecurityAlert) -> None:
    planner = make_planner()
    plan = planner.create_plan(alert)

    first = planner.decide_next_action(context_with(plan, 0, alert, successes=0))
    network = planner.decide_next_action(context_with(plan, 2, alert, successes=0))
    indicator = planner.decide_next_action(context_with(plan, 3, alert, successes=0))

    assert first.arguments is not None
    assert first.arguments["case_id"] == CASE_ID
    assert first.arguments["process_name"] == alert.process_name
    assert network.arguments is not None
    assert network.arguments["dst_ip"] == alert.dst_ip
    assert indicator.arguments is not None
    assert indicator.arguments["indicator"] == alert.dst_ip


def test_planner_progresses_through_planned_calls(alert: SecurityAlert) -> None:
    planner = make_planner()
    plan = planner.create_plan(alert)

    first = planner.decide_next_action(context_with(plan, 0, alert, successes=0))
    second = planner.decide_next_action(context_with(plan, 0, alert, successes=1))
    finish = planner.decide_next_action(context_with(plan, 0, alert, successes=2))

    assert first.action is PlannerAction.CALL_TOOL
    assert second.action is PlannerAction.CALL_TOOL
    assert first.arguments != second.arguments
    assert finish.action is PlannerAction.COMPLETE_STEP
    assert finish.tool_name is None
    assert finish.arguments is None


def test_failed_calls_do_not_advance_the_planner(alert: SecurityAlert) -> None:
    planner = make_planner()
    plan = planner.create_plan(alert)

    decision = planner.decide_next_action(context_with(plan, 0, alert, successes=0, failures=1))

    assert decision.action is PlannerAction.CALL_TOOL
    assert decision.arguments == {"case_id": CASE_ID, "process_name": alert.process_name}


def test_step_without_planned_calls_completes_immediately(
    alert: SecurityAlert,
) -> None:
    alert_without_file = alert.model_copy(update={"command_line": "cmd /c echo hello"})
    planner = make_planner()
    plan = planner.create_plan(alert_without_file)
    file_step_index = 1

    assert plan.steps[file_step_index].suggested_tool is None
    decision = planner.decide_next_action(
        context_with(plan, file_step_index, alert_without_file, successes=0)
    )

    assert decision.action is PlannerAction.COMPLETE_STEP


def test_unknown_steps_complete_without_tool_calls(alert: SecurityAlert) -> None:
    planner = make_planner()
    foreign_plan = plan_factory(step_factory(step_id="STEP-999999"))
    context = PlanningContext(
        alert=alert, plan=foreign_plan, current_step=foreign_plan.steps[0]
    )

    decision = planner.decide_next_action(context)

    assert decision.action is PlannerAction.COMPLETE_STEP


def test_planner_is_deterministic_across_instances(alert: SecurityAlert) -> None:
    first_planner = make_planner()
    second_planner = make_planner()

    first_plan = first_planner.create_plan(alert)
    second_plan = second_planner.create_plan(alert)
    first_decision = first_planner.decide_next_action(context_with(first_plan, 2, alert, successes=0))
    second_decision = second_planner.decide_next_action(
        context_with(second_plan, 2, alert, successes=0)
    )

    assert first_plan.model_dump() == second_plan.model_dump()
    assert first_decision.model_dump() == second_decision.model_dump()


def test_planner_never_touches_a_dataset(alert: SecurityAlert) -> None:
    planner = make_planner(case_id="CASE-does-not-exist")

    plan = planner.create_plan(alert)
    decision = planner.decide_next_action(context_with(plan, 0, alert, successes=0))

    assert decision.arguments is not None
    assert decision.arguments["case_id"] == "CASE-does-not-exist"


def test_helper_extracts_the_last_file_token() -> None:
    command_line = (
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 628 "
        "C:\\Windows\\Temp\\lsass.dmp full"
    )

    assert last_file_token(command_line, "rundll32.exe") == "lsass.dmp"
    assert last_file_token(command_line, None) == "lsass.dmp"
    assert last_file_token(None, "rundll32.exe") is None
    assert last_file_token("cmd.exe /c echo hello", "cmd.exe") == "cmd.exe"
    assert last_file_token("nothing to see here", None) is None


@pytest.mark.parametrize(
    ("process_name", "expected"),
    [
        ("powershell.exe", "powershell"),
        ("C:\\Windows\\System32\\rundll32.exe", "rundll32"),
        ("/usr/bin/wscript.exe", "wscript"),
        (None, None),
        ("", None),
    ],
)
def test_helper_derives_base_process_name(process_name: str | None, expected: str | None) -> None:
    assert base_process_name(process_name) == expected
