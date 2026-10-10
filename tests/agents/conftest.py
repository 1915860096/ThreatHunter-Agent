"""Fixtures for the T07 LLM planner tests.

No test ever performs a real network request: :class:`FakeLLMClient` answers
from a scripted list or from a factory that inspects the prompt, and records
every prompt it received.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Any

import pytest

from app.agents import (
    AgentContextBuilder,
    AgentDecisionTraceRecorder,
    DeterministicPlanner,
    LLMBudget,
    LLMClient,
    LLMClientError,
    LLMCompletion,
    LLMPlanner,
)
from app.runtime.contracts import PlanningContext
from app.schemas.alert import SecurityAlert
from app.schemas.investigation import InvestigationPlan

CASE_ID = "CASE-001"


class FakeLLMClient:
    """Programmable client double; the last response repeats."""

    name = "fake-llm"
    model = "fake-model"

    def __init__(
        self,
        responses: Sequence[str] | None = None,
        *,
        factory: Callable[[Sequence[dict[str, str]], int], str] | None = None,
        error: LLMClientError | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
    ) -> None:
        self._responses = list(responses or [])
        self._factory = factory
        self._error = error
        self._prompt_tokens = prompt_tokens
        self._completion_tokens = completion_tokens
        self.requests: list[list[dict[str, str]]] = []

    def complete(
        self,
        messages: Sequence[dict[str, str]],
        *,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMCompletion:
        recorded = [dict(message) for message in messages]
        self.requests.append(recorded)
        if self._error is not None:
            raise self._error
        if self._factory is not None:
            content = self._factory(recorded, len(self.requests) - 1)
        elif self._responses:
            index = min(len(self.requests) - 1, len(self._responses) - 1)
            content = self._responses[index]
        else:
            content = json.dumps(
                {
                    "action": "complete_step",
                    "tool_name": None,
                    "arguments": None,
                    "rationale": "fake default: nothing else to query",
                }
            )
        return LLMCompletion(
            content=content,
            model=model or self.model,
            prompt_tokens=self._prompt_tokens,
            completion_tokens=self._completion_tokens,
        )

    @property
    def request_count(self) -> int:
        return len(self.requests)

    def prompt_payload(self, index: int = -1) -> dict[str, Any]:
        """Return the AgentContext JSON of one recorded request."""
        return json.loads(self.requests[index][1]["content"])


def call_tool_response(
    tool_name: str, arguments: dict[str, Any] | None = None, rationale: str = "fake call"
) -> str:
    """Build a ``call_tool`` response body."""
    return json.dumps(
        {
            "action": "call_tool",
            "tool_name": tool_name,
            "arguments": arguments if arguments is not None else {"case_id": CASE_ID},
            "rationale": rationale,
        }
    )


def complete_step_response(rationale: str = "fake complete") -> str:
    """Build a ``complete_step`` response body."""
    return json.dumps(
        {
            "action": "complete_step",
            "tool_name": None,
            "arguments": None,
            "rationale": rationale,
        }
    )


@pytest.fixture
def fake_client() -> FakeLLMClient:
    return FakeLLMClient([complete_step_response()])


@pytest.fixture
def planner_factory() -> Callable[..., LLMPlanner]:
    """Build an LLMPlanner around a client double."""

    def _build(
        client: LLMClient,
        *,
        case_id: str = CASE_ID,
        budget: LLMBudget | None = None,
        mode: str = "scripted",
        context_builder: AgentContextBuilder | None = None,
        recorder: AgentDecisionTraceRecorder | None = None,
    ) -> LLMPlanner:
        return LLMPlanner(
            case_id=case_id,
            client=client,
            budget=budget or LLMBudget(),
            model="fake-model",
            mode=mode,
            context_builder=context_builder,
            recorder=recorder
            or AgentDecisionTraceRecorder(mode=mode, model="fake-model"),
        )

    return _build


@pytest.fixture
def planning_context_factory(alert: SecurityAlert) -> Callable[..., PlanningContext]:
    """Build a real T05 PlanningContext for the deterministic CASE-001 plan."""

    def _build(
        *,
        step_index: int = 0,
        plan: InvestigationPlan | None = None,
        previous_tool_calls: Sequence[Any] = (),
        previous_tool_results: Sequence[Any] = (),
        remaining_tool_budget: int = 20,
        remaining_step_budget: int = 5,
    ) -> PlanningContext:
        resolved = plan or DeterministicPlanner(case_id=CASE_ID).create_plan(alert)
        return PlanningContext(
            alert=alert,
            plan=resolved,
            current_step=resolved.steps[step_index],
            previous_tool_calls=list(previous_tool_calls),
            previous_tool_results=list(previous_tool_results),
            remaining_tool_budget=remaining_tool_budget,
            remaining_step_budget=remaining_step_budget,
        )

    return _build
