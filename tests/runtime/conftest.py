"""Fixtures and test doubles for the T05 orchestration runtime tests.

Everything is deterministic: the clock is a ticking counter, IDs come from
``SequentialIdGenerator`` and tool execution is either the real T04 executor
(integration tests) or a scripted stub.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from app.agents import DeterministicPlanner
from app.benchmark import BenchmarkLoader
from app.runtime import (
    InMemoryRuntimeStore,
    InvestigationBudget,
    InvestigationRuntime,
    PlannerAction,
    PlannerDecision,
    RetryPolicy,
    SequentialIdGenerator,
)
from app.schemas.alert import SecurityAlert
from app.schemas.investigation import (
    InvestigationPlan,
    InvestigationStep,
    InvestigationStepStatus,
)
from app.schemas.tools import ToolCall, ToolResult
from app.tools import ToolExecutor

CASE_ID = "CASE-001"
START_TIME = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)


class TickingClock:
    """Deterministic clock returning a new UTC timestamp on every call."""

    def __init__(self, start: datetime = START_TIME, step_seconds: float = 1.0) -> None:
        self._now = start
        self._step = timedelta(seconds=step_seconds)

    def __call__(self) -> datetime:
        current = self._now
        self._now += self._step
        return current


class ScriptedPlanner:
    """Planner double returning canned plans and decisions."""

    def __init__(
        self,
        *,
        plan: InvestigationPlan | None = None,
        decisions: Sequence[PlannerDecision] | None = None,
        decision_factory: Callable[[Any, int], PlannerDecision] | None = None,
        create_plan_error: Exception | None = None,
        decide_error: Exception | None = None,
    ) -> None:
        self._plan = plan if plan is not None else plan_factory()
        self._decisions = list(decisions or [])
        self._decision_factory = decision_factory
        self._create_plan_error = create_plan_error
        self._decide_error = decide_error
        self.decide_calls = 0
        self.contexts: list[Any] = []

    def create_plan(self, alert: SecurityAlert) -> InvestigationPlan:
        if self._create_plan_error is not None:
            raise self._create_plan_error
        return self._plan.model_copy(deep=True)

    def decide_next_action(self, context: Any) -> PlannerDecision:
        if self._decide_error is not None:
            raise self._decide_error
        self.contexts.append(context)
        if self._decision_factory is not None:
            decision = self._decision_factory(context, self.decide_calls)
        elif self._decisions:
            index = min(self.decide_calls, len(self._decisions) - 1)
            decision = self._decisions[index]
        else:
            decision = PlannerDecision(
                action=PlannerAction.COMPLETE_STEP, rationale="step has no planned work"
            )
        self.decide_calls += 1
        return decision


class StubExecutor:
    """Executor double returning scripted ``ToolResult`` outcomes."""

    def __init__(
        self,
        outcomes: Sequence[tuple[bool, str | None]],
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._outcomes = list(outcomes)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.calls: list[ToolCall] = []

    def execute(self, tool_call: ToolCall) -> ToolResult:
        self.calls.append(tool_call.model_copy(deep=True))
        if not self._outcomes:
            raise AssertionError("StubExecutor ran out of scripted outcomes")
        success, error = self._outcomes.pop(0)
        return ToolResult(
            tool_result_id=f"TR-{len(self.calls):04d}",
            tool_call_id=tool_call.tool_call_id,
            tool_name=tool_call.tool_name,
            success=success,
            data={"scripted": True} if success else None,
            error=error,
            latency_ms=len(self.calls),
            returned_at=self._clock(),
        )


class ExplodingExecutor:
    """Executor double that always raises (defensive runtime path)."""

    def __init__(self, message: str = "token=SECRET-VALUE-KEEP-OUT") -> None:
        self._message = message
        self.calls = 0

    def execute(self, tool_call: ToolCall) -> ToolResult:
        self.calls += 1
        raise RuntimeError(self._message)


def step_factory(
    *,
    step_id: str = "STEP-000001",
    order: int = 1,
    action: str = "Collect endpoint activity",
    rationale: str = "Because the alert names a process.",
    suggested_tool: str | None = "search_endpoint_events",
    status: InvestigationStepStatus = InvestigationStepStatus.PENDING,
) -> InvestigationStep:
    """Build one pending step."""
    return InvestigationStep(
        step_id=step_id,
        order=order,
        action=action,
        rationale=rationale,
        suggested_tool=suggested_tool,
        status=status,
    )


def plan_factory(
    *steps: InvestigationStep,
    plan_id: str = "PLAN-000001",
    incident_id: str = "INC-000000",
    alert_id: str = "ALT-001",
) -> InvestigationPlan:
    """Build a plan holding the given steps."""
    return InvestigationPlan(
        plan_id=plan_id,
        incident_id=incident_id,
        alert_id=alert_id,
        objective="Investigate the alert deterministically.",
        steps=list(steps) or [step_factory()],
        created_at=START_TIME,
    )


def call_tool(
    tool_name: str = "search_endpoint_events",
    arguments: dict[str, Any] | None = None,
    rationale: str = "Query the telemetry.",
) -> PlannerDecision:
    """Build a ``call_tool`` decision."""
    return PlannerDecision(
        action=PlannerAction.CALL_TOOL,
        tool_name=tool_name,
        arguments=arguments if arguments is not None else {"case_id": CASE_ID},
        rationale=rationale,
    )


def complete_step(rationale: str = "Nothing left to query.") -> PlannerDecision:
    """Build a ``complete_step`` decision."""
    return PlannerDecision(action=PlannerAction.COMPLETE_STEP, rationale=rationale)


def fail_step(rationale: str = "The step cannot be completed.") -> PlannerDecision:
    """Build a ``fail_step`` decision."""
    return PlannerDecision(action=PlannerAction.FAIL_STEP, rationale=rationale)


@pytest.fixture
def clock() -> TickingClock:
    return TickingClock()


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


@pytest.fixture
def alert(loader: BenchmarkLoader) -> SecurityAlert:
    return loader.load_initial_alert(CASE_ID)


@pytest.fixture
def executor(loader: BenchmarkLoader, clock: TickingClock) -> ToolExecutor:
    return ToolExecutor(loader=loader, clock=clock)


@pytest.fixture
def store() -> InMemoryRuntimeStore:
    return InMemoryRuntimeStore()


@pytest.fixture
def planner(clock: TickingClock) -> DeterministicPlanner:
    return DeterministicPlanner(
        case_id=CASE_ID, id_generator=SequentialIdGenerator(), clock=clock
    )


@pytest.fixture
def runtime_factory(
    clock: TickingClock, executor: ToolExecutor, store: InMemoryRuntimeStore
) -> Callable[..., InvestigationRuntime]:
    """Build a runtime with deterministic defaults and per-test overrides."""

    def _build(planner: Any, **overrides: Any) -> InvestigationRuntime:
        kwargs: dict[str, Any] = {
            "executor": executor,
            "id_generator": SequentialIdGenerator(),
            "clock": clock,
            "retry_policy": RetryPolicy(),
            "budget": InvestigationBudget(),
            "store": store,
        }
        kwargs.update(overrides)
        return InvestigationRuntime(planner, **kwargs)

    return _build


@pytest.fixture
def dataset_dir(tmp_path: Path) -> Path:
    """A writable copy of the shipped T03 dataset."""
    target = tmp_path / "datasets"
    shutil.copytree(BenchmarkLoader().dataset_root, target)
    return target
