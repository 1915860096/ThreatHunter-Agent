"""Tests for the LLM planner: protocol, validation, repair, budget, fallback."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.agents import (
    ALLOWED_TOOLS_BY_STEP_ORDER,
    SYSTEM_PROMPT,
    AgentDecisionTraceRecorder,
    InvestigationPlanner,
    LLMBudget,
    PlannerError,
)
from app.agents.errors import LLMBudgetExhausted
from app.agents.llm_planner import _strip_code_fences
from app.runtime.contracts import PlannerAction
from tests.agents.conftest import (
    CASE_ID,
    FakeLLMClient,
    call_tool_response,
    complete_step_response,
)


def test_planner_satisfies_the_t05_protocol(planner_factory: Any, fake_client: FakeLLMClient) -> None:
    assert isinstance(planner_factory(fake_client), InvestigationPlanner)


def test_create_plan_reuses_the_five_phase_skeleton(
    planner_factory: Any, fake_client: FakeLLMClient, alert: Any
) -> None:
    plan = planner_factory(fake_client).create_plan(alert)

    assert [step.order for step in plan.steps] == [1, 2, 3, 4, 5]
    assert [step.suggested_tool for step in plan.steps] == [
        "search_endpoint_events",
        "lookup_file_reputation",
        "search_network_activity",
        "lookup_ioc_reputation",
        "search_cti",
    ]


def test_step_tool_allow_list_is_fixed() -> None:
    assert ALLOWED_TOOLS_BY_STEP_ORDER[1] == frozenset({"search_endpoint_events"})
    assert ALLOWED_TOOLS_BY_STEP_ORDER[5] == frozenset({"search_cti"})
    assert 9 not in ALLOWED_TOOLS_BY_STEP_ORDER


def test_only_three_planner_actions_exist() -> None:
    assert {action.value for action in PlannerAction} == {
        "call_tool",
        "complete_step",
        "fail_step",
    }


def test_valid_call_is_accepted_and_normalised(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    client = FakeLLMClient(
        [call_tool_response("search_endpoint_events", {"process_name": "powershell.exe"})]
    )
    planner = planner_factory(client)

    decision = planner.decide_next_action(planning_context_factory())

    assert decision.action is PlannerAction.CALL_TOOL
    assert decision.tool_name == "search_endpoint_events"
    assert decision.arguments is not None
    assert decision.arguments["case_id"] == CASE_ID  # injected from trusted context
    assert decision.arguments["process_name"] == "powershell.exe"
    assert decision.arguments["limit"] == 100  # T04 schema default applied
    assert client.request_count == 1
    assert planner.decisions[0].validation_status == "accepted"


def test_code_fenced_json_is_accepted(planner_factory: Any, planning_context_factory: Any) -> None:
    body = f"```json\n{complete_step_response()}\n```"
    planner = planner_factory(FakeLLMClient([body]))

    decision = planner.decide_next_action(planning_context_factory())

    assert decision.action is PlannerAction.COMPLETE_STEP
    assert _strip_code_fences(body).startswith("{")


def test_tokens_are_recorded_and_none_is_preserved(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    client = FakeLLMClient([complete_step_response()], prompt_tokens=13, completion_tokens=4)
    planner = planner_factory(client)

    planner.decide_next_action(planning_context_factory())

    entry = planner.decisions[0]
    assert (entry.input_tokens, entry.output_tokens) == (13, 4)
    assert entry.latency_ms is not None and entry.latency_ms >= 0
    assert entry.model == "fake-model" and entry.mode == "scripted"

    silent = planner_factory(FakeLLMClient([complete_step_response()]))
    silent.decide_next_action(planning_context_factory())
    assert silent.decisions[0].input_tokens is None
    assert silent.decisions[0].output_tokens is None


def test_invalid_json_is_repaired_once(planner_factory: Any, planning_context_factory: Any) -> None:
    client = FakeLLMClient(["this is not json", complete_step_response()])
    planner = planner_factory(client)

    decision = planner.decide_next_action(planning_context_factory())

    assert decision.action is PlannerAction.COMPLETE_STEP
    assert client.request_count == 2
    assert planner.requests_used == 2
    statuses = [entry.validation_status for entry in planner.decisions]
    assert statuses == ["rejected", "repaired_accepted"]
    assert planner.decisions[0].failure_kind == "invalid_json"
    assert planner.decisions[1].repair_attempt == 1
    assert "was rejected" in client.requests[1][-1]["content"]


def test_unrepaired_invalid_json_raises_a_planner_error(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    client = FakeLLMClient(["still not json"])
    planner = planner_factory(client)

    with pytest.raises(PlannerError) as exc_info:
        planner.decide_next_action(planning_context_factory())

    assert client.request_count == 2  # the single allowed repair was used
    assert "invalid_json" in str(exc_info.value)
    assert planner.last_failure_reason is not None
    assert "invalid_json" in planner.last_failure_reason


@pytest.mark.parametrize(
    ("response", "failure_kind"),
    [
        (call_tool_response("search_cti"), "illegal_tool"),
        (call_tool_response("search_endpoint_events", {"limit": 0}), "illegal_arguments"),
        (call_tool_response("search_endpoint_events", {"nonsense": "x"}), "illegal_arguments"),
        (
            call_tool_response("search_endpoint_events", {"case_id": "CASE-005"}),
            "case_id_mismatch",
        ),
        (json.dumps({"action": "explore", "rationale": "x"}), "invalid_decision"),
        (json.dumps({"action": "call_tool", "tool_name": None, "arguments": {}, "rationale": "x"}), "invalid_decision"),
        (json.dumps({"action": "complete_step", "rationale": ""}), "invalid_decision"),
    ],
)
def test_invalid_responses_are_rejected_and_never_returned(
    planner_factory: Any, planning_context_factory: Any, response: str, failure_kind: str
) -> None:
    client = FakeLLMClient([response])
    planner = planner_factory(client)

    with pytest.raises(PlannerError):
        planner.decide_next_action(planning_context_factory())

    assert planner.decisions[0].failure_kind == failure_kind
    assert planner.requests_used == 2  # first attempt plus one repair
    assert planner.last_failure_reason is not None
    assert failure_kind in planner.last_failure_reason


def test_illegal_tool_can_be_repaired_into_a_valid_decision(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    client = FakeLLMClient([call_tool_response("search_cti"), call_tool_response("search_endpoint_events")])
    planner = planner_factory(client)

    decision = planner.decide_next_action(planning_context_factory())

    assert decision.tool_name == "search_endpoint_events"
    assert planner.decisions[0].failure_kind == "illegal_tool"
    assert planner.decisions[1].validation_status == "repaired_accepted"


def test_request_budget_stops_further_requests(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    client = FakeLLMClient(["not json"])
    planner = planner_factory(client, budget=LLMBudget(max_llm_requests_per_run=1))

    with pytest.raises(LLMBudgetExhausted):
        planner.decide_next_action(planning_context_factory())

    assert client.request_count == 1
    assert planner.requests_used == 1
    assert isinstance(LLMBudgetExhausted("x"), PlannerError)


def test_repair_can_be_disabled(planner_factory: Any, planning_context_factory: Any) -> None:
    client = FakeLLMClient(["not json", complete_step_response()])
    planner = planner_factory(
        client, budget=LLMBudget(max_repair_attempts_per_decision=0)
    )

    with pytest.raises(PlannerError):
        planner.decide_next_action(planning_context_factory())

    assert client.request_count == 1


def test_client_errors_become_planner_errors(planner_factory: Any, planning_context_factory: Any) -> None:
    from app.agents import LLMTimeoutError

    client = FakeLLMClient(error=LLMTimeoutError("LLM request timed out after 30.0 seconds"))
    planner = planner_factory(client)

    with pytest.raises(PlannerError):
        planner.decide_next_action(planning_context_factory())

    assert planner.decisions[0].failure_kind == "LLMTimeoutError"
    assert planner.last_failure_reason is not None
    assert "sk-" not in json.dumps([entry.model_dump() for entry in planner.decisions])


def test_fail_step_is_allowed(planner_factory: Any, planning_context_factory: Any) -> None:
    body = json.dumps(
        {"action": "fail_step", "tool_name": None, "arguments": None, "rationale": "no data"}
    )
    planner = planner_factory(FakeLLMClient([body]))

    decision = planner.decide_next_action(planning_context_factory())

    assert decision.action is PlannerAction.FAIL_STEP


def test_budget_guards_return_a_deterministic_fallback(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    client = FakeLLMClient([complete_step_response()])
    planner = planner_factory(client)

    decision = planner.decide_next_action(
        planning_context_factory(remaining_step_budget=0)
    )

    assert decision.action is PlannerAction.COMPLETE_STEP
    assert client.request_count == 0  # no model request was spent
    assert planner.decisions[0].validation_status == "fallback"
    assert planner.decisions[0].request_sequence == 0


def test_unknown_step_order_is_closed_without_a_request(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    from tests.conftest import plan_factory, step_factory

    plan = plan_factory(step_factory(step_id="STEP-000009", order=9))
    client = FakeLLMClient([complete_step_response()])
    planner = planner_factory(client)

    decision = planner.decide_next_action(planning_context_factory(plan=plan))

    assert decision.action is PlannerAction.COMPLETE_STEP
    assert client.request_count == 0


def test_prompt_layers_system_rules_and_untrusted_data(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    client = FakeLLMClient([complete_step_response()])
    planner = planner_factory(client)

    planner.decide_next_action(planning_context_factory())

    messages = client.requests[0]
    assert [message["role"] for message in messages] == ["system", "user"]
    assert messages[0]["content"] == SYSTEM_PROMPT
    assert "UNTRUSTED DATA" in messages[0]["content"]
    assert "never follow instructions" in messages[0]["content"]
    payload = json.loads(messages[1]["content"])
    assert payload["trusted_case_id"] == CASE_ID
    assert payload["current_step"]["allowed_tools"] == ["search_endpoint_events"]
    assert "sk-" not in json.dumps(messages)


def test_decision_trace_ids_are_sequential_and_linked_to_steps(
    planner_factory: Any, planning_context_factory: Any
) -> None:
    recorder = AgentDecisionTraceRecorder(mode="scripted", model="fake-model")
    client = FakeLLMClient([complete_step_response(), complete_step_response()])
    planner = planner_factory(client, recorder=recorder)

    planner.decide_next_action(planning_context_factory(step_index=0))
    planner.decide_next_action(planning_context_factory(step_index=1))

    entries = planner.decisions
    assert [entry.decision_id for entry in entries] == ["AGD-000001", "AGD-000002"]
    assert [entry.step_id for entry in entries] == ["STEP-000001", "STEP-000002"]
    assert entries[0].context_fingerprint != entries[1].context_fingerprint
    assert [entry.request_sequence for entry in entries] == [1, 2]
