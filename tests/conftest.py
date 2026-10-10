"""Shared fixtures for the T06 test suites (evidence, reporting, demo).

The fixtures build either the real closed loop (deterministic clock and id
generator) or scripted ToolCall/ToolResult pairs, so payload edge cases can be
tested without going through the runtime.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any

import pytest

from app.agents import DeterministicPlanner
from app.benchmark import BenchmarkLoader
from app.evidence import DeterministicEvidenceExtractor
from app.reporting import DeterministicSummaryBuilder
from app.runtime import InvestigationRuntime, SequentialIdGenerator
from app.runtime.contracts import InvestigationRun, RuntimeStatus, StopReason
from app.schemas.alert import SecurityAlert
from app.schemas.tools import ToolCall, ToolResult
from app.tools import ToolExecutor
from tests.runtime.conftest import TickingClock, plan_factory, step_factory

CASE_ID = "CASE-001"
START = datetime(2026, 6, 1, 0, 0, tzinfo=timezone.utc)
INCIDENT_ID = "INC-000001"
STEP_ID = "STEP-000001"


@pytest.fixture
def loader() -> BenchmarkLoader:
    return BenchmarkLoader()


@pytest.fixture
def alert(loader: BenchmarkLoader) -> SecurityAlert:
    return loader.load_initial_alert(CASE_ID)


@pytest.fixture
def extractor() -> DeterministicEvidenceExtractor:
    return DeterministicEvidenceExtractor(case_id=CASE_ID)


@pytest.fixture
def summary_builder() -> DeterministicSummaryBuilder:
    return DeterministicSummaryBuilder()


@pytest.fixture
def case_run_factory(loader: BenchmarkLoader) -> Callable[..., InvestigationRun]:
    """Run the real closed loop for a case with a deterministic clock."""

    def _build(case_id: str = CASE_ID) -> InvestigationRun:
        clock = TickingClock()
        runtime = InvestigationRuntime(
            DeterministicPlanner(
                case_id=case_id, id_generator=SequentialIdGenerator(), clock=clock
            ),
            executor=ToolExecutor(loader=loader, clock=clock),
            id_generator=SequentialIdGenerator(),
            clock=clock,
        )
        return runtime.run(loader.load_initial_alert(case_id))

    return _build


@pytest.fixture
def real_run(case_run_factory: Callable[..., InvestigationRun]) -> InvestigationRun:
    return case_run_factory(CASE_ID)


@pytest.fixture
def tool_call_factory() -> Callable[..., ToolCall]:
    def _build(
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        *,
        index: int = 1,
    ) -> ToolCall:
        return ToolCall(
            tool_call_id=f"TC-{index:06d}",
            incident_id=INCIDENT_ID,
            step_id=STEP_ID,
            tool_name=tool_name,
            arguments=arguments if arguments is not None else {"case_id": CASE_ID},
            rationale="scripted test call",
            status="succeeded",
            requested_at=START,
            started_at=START,
            completed_at=START,
        )

    return _build


@pytest.fixture
def tool_result_factory() -> Callable[..., ToolResult]:
    def _build(
        call: ToolCall,
        data: Any = None,
        *,
        index: int = 1,
        success: bool = True,
        error: str | None = None,
    ) -> ToolResult:
        return ToolResult(
            tool_result_id=f"TR-{index:04d}",
            tool_call_id=call.tool_call_id,
            tool_name=call.tool_name,
            success=success,
            data=data,
            error=error,
            latency_ms=0,
            returned_at=START,
        )

    return _build


@pytest.fixture
def run_factory(alert: SecurityAlert) -> Callable[..., InvestigationRun]:
    """Assemble a run from scripted (ToolCall, ToolResult) pairs."""

    def _build(
        pairs: Sequence[tuple[ToolCall, ToolResult]],
        *,
        plan: Any = None,
        status: RuntimeStatus = RuntimeStatus.COMPLETED,
        stop_reason: StopReason = StopReason.COMPLETED,
    ) -> InvestigationRun:
        return InvestigationRun(
            incident_id=INCIDENT_ID,
            alert=alert,
            plan=plan if plan is not None else plan_factory(step_factory(step_id=STEP_ID)),
            tool_calls=[call for call, _ in pairs],
            tool_results=[result for _, result in pairs],
            trajectory=[],
            status=status,
            stop_reason=stop_reason,
            started_at=START,
            completed_at=START,
        )

    return _build
