"""The deterministic investigation orchestration runtime.

The runtime owns everything that happens between an alert and a finished run:
incident creation, planning, step and tool-call lifecycles, retries, budget
enforcement, trajectory recording and in-memory persistence. It performs no
security reasoning: it never interprets a tool result beyond success/failure.

Termination semantics (documented policy):

* every step completes or fails; a failing step does not by itself end the run;
* a tool failure that the retry policy refuses to retry ends the step; failures
  accumulate against ``budget.max_failures``;
* an ``invalid_arguments`` or ``unknown_tool`` failure (or a retry-exhausted
  argument failure) is unrecoverable for a deterministic runtime and ends the
  run with ``StopReason.UNRECOVERABLE_TOOL_ERROR``;
* budget blocks end the run with ``RuntimeStatus.BUDGET_EXHAUSTED``;
* a planner exception ends the run with ``StopReason.PLANNER_FAILED``;
* a run that finishes with every step completed is ``completed``; a run whose
  steps all became terminal but at least one failed is ``failed`` with
  ``StopReason.STEP_FAILED``.

Counting semantics:

* ``total_tool_calls`` counts every dispatched execution attempt, whether it
  returned a ``ToolResult`` or the executor raised;
* ``total_tool_failures`` counts every failed attempt: a returned failure and
  an executor exception both count once, and retries count as separate
  attempts;
* each attempt is recorded exactly once, so no path double-counts.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Final

from app.runtime.budget import InvestigationBudget
from app.runtime.contracts import (
    InvestigationRun,
    InvestigationRuntimeState,
    PlannerAction,
    PlannerDecision,
    PlanningContext,
    RuntimeStatus,
    StopReason,
    TrajectoryEventType,
)
from app.runtime.ids import IdGenerator, SequentialIdGenerator
from app.runtime.retry import RetryPolicy, ToolFailureKind, classify_tool_failure
from app.runtime.store import InMemoryRuntimeStore, RuntimeStore
from app.runtime.trajectory import TrajectoryRecorder
from app.schemas.alert import SecurityAlert
from app.schemas.investigation import (
    InvestigationPlan,
    InvestigationStep,
    InvestigationStepStatus,
)
from app.schemas.tools import ToolCall, ToolCallStatus
from app.tools.executor import ToolExecutor

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from app.agents.planner import InvestigationPlanner

BUDGET_STOP_REASONS: Final[frozenset[StopReason]] = frozenset(
    {
        StopReason.MAX_STEPS_EXCEEDED,
        StopReason.MAX_TOOL_CALLS_EXCEEDED,
        StopReason.MAX_TOOL_CALLS_PER_STEP_EXCEEDED,
        StopReason.TOOL_FAILURE_LIMIT,
    }
)

#: Failure kind recorded when the T04 executor raised instead of returning a
#: ``ToolResult``. Fixed by design: no exception message or traceback is kept.
EXECUTOR_EXCEPTION_FAILURE_KIND: Final[str] = "executor_exception"


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class _CallOutcome:
    """Result of executing one planned tool call (including its retries)."""

    succeeded: bool
    stop_reason: StopReason | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _StepOutcome:
    """Terminal status of one step, optionally with a run-level stop."""

    status: InvestigationStepStatus
    stop_reason: StopReason | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class InvestigationRuntime:
    """Runs one alert through planning and tool execution, deterministically.

    Every collaborator is injectable: ``planner``, ``executor``,
    ``id_generator``, ``clock``, ``retry_policy``, ``budget`` and ``store``.
    """

    def __init__(
        self,
        planner: "InvestigationPlanner",
        executor: ToolExecutor | None = None,
        id_generator: IdGenerator | None = None,
        clock: Callable[[], datetime] | None = None,
        retry_policy: RetryPolicy | None = None,
        budget: InvestigationBudget | None = None,
        store: RuntimeStore | None = None,
    ) -> None:
        self._planner = planner
        self._executor = executor or ToolExecutor()
        self._id_generator = id_generator or SequentialIdGenerator()
        self._clock = clock or _default_clock
        self._retry_policy = retry_policy or RetryPolicy()
        self._budget = budget or InvestigationBudget()
        self._store = store or InMemoryRuntimeStore()

    def run(self, alert: SecurityAlert) -> InvestigationRun:
        """Investigate ``alert`` and return the T05 run (never raises)."""
        incident_id = self._id_generator.next_incident_id()
        started_at = self._clock()
        trajectory = TrajectoryRecorder(incident_id=incident_id, clock=self._clock)
        state = InvestigationRuntimeState(
            incident_id=incident_id,
            alert=alert,
            started_at=started_at,
            updated_at=started_at,
        )
        self._store.save_state(state)
        trajectory.record(
            TrajectoryEventType.INVESTIGATION_STARTED,
            details={
                "alert_id": alert.alert_id,
                "severity": alert.severity.value,
                "event_type": alert.event_type,
                "source": alert.source,
            },
        )

        try:
            return self._drive(state, trajectory)
        except Exception as exc:  # noqa: BLE001 - the runtime must never leak an exception
            return self._terminate(
                state,
                trajectory,
                status=RuntimeStatus.FAILED,
                stop_reason=StopReason.RUNTIME_ERROR,
                event_type=TrajectoryEventType.INVESTIGATION_FAILED,
                details={"failure": "unexpected_runtime_error", "error_type": type(exc).__name__},
            )

    # Driving -----------------------------------------------------------------

    def _drive(
        self, state: InvestigationRuntimeState, trajectory: TrajectoryRecorder
    ) -> InvestigationRun:
        state.status = RuntimeStatus.PLANNING
        self._touch(state)

        try:
            plan = self._planner.create_plan(state.alert)
        except Exception as exc:  # noqa: BLE001 - planner failures are reported, not raised
            return self._terminate(
                state,
                trajectory,
                status=RuntimeStatus.FAILED,
                stop_reason=StopReason.PLANNER_FAILED,
                event_type=TrajectoryEventType.INVESTIGATION_FAILED,
                details={"failure": "planner_exception", "error_type": type(exc).__name__},
            )

        plan = self._stamp_incident_id(plan, state.incident_id)
        state.plan = plan
        state.status = RuntimeStatus.RUNNING
        self._touch(state)
        trajectory.record(
            TrajectoryEventType.PLAN_CREATED,
            details={
                "plan_id": plan.plan_id,
                "alert_id": plan.alert_id,
                "objective": plan.objective,
                "step_count": len(plan.steps),
            },
        )
        self._store.save_state(state)

        steps_started = 0
        failed_steps = 0
        for step in plan.steps:
            stop_reason = self._budget.stop_reason_for_step_start(steps_started=steps_started)
            if stop_reason is not None:
                return self._terminate(
                    state,
                    trajectory,
                    status=RuntimeStatus.BUDGET_EXHAUSTED,
                    stop_reason=stop_reason,
                    event_type=TrajectoryEventType.BUDGET_EXHAUSTED,
                    details={
                        "stop_reason": stop_reason.value,
                        "steps_started": steps_started,
                        "plan_step_count": len(plan.steps),
                    },
                )

            steps_started += 1
            self._start_step(state, step, trajectory)
            outcome = self._run_step(state, step, trajectory)

            if outcome.stop_reason is not None:
                self._finish_step(
                    state,
                    step,
                    trajectory,
                    status=InvestigationStepStatus.FAILED,
                    error=outcome.error or outcome.stop_reason.value,
                    details=outcome.details,
                )
                return self._terminate_for_stop_reason(state, trajectory, outcome.stop_reason)

            if outcome.status is InvestigationStepStatus.FAILED:
                failed_steps += 1
                self._finish_step(
                    state,
                    step,
                    trajectory,
                    status=InvestigationStepStatus.FAILED,
                    error=outcome.error,
                    details=outcome.details,
                )
                continue

            self._finish_step(
                state,
                step,
                trajectory,
                status=InvestigationStepStatus.COMPLETED,
                error=None,
                details=outcome.details,
            )

        if failed_steps:
            return self._terminate(
                state,
                trajectory,
                status=RuntimeStatus.FAILED,
                stop_reason=StopReason.STEP_FAILED,
                event_type=TrajectoryEventType.INVESTIGATION_FAILED,
                details={"failed_steps": failed_steps, "total_steps": steps_started},
            )

        return self._terminate(
            state,
            trajectory,
            status=RuntimeStatus.COMPLETED,
            stop_reason=StopReason.COMPLETED,
            event_type=TrajectoryEventType.INVESTIGATION_COMPLETED,
            details={
                "steps_completed": steps_started,
                "tool_calls": state.total_tool_calls,
                "tool_failures": state.total_tool_failures,
            },
        )

    # Steps -------------------------------------------------------------------

    def _start_step(
        self,
        state: InvestigationRuntimeState,
        step: InvestigationStep,
        trajectory: TrajectoryRecorder,
    ) -> None:
        state.current_step_id = step.step_id
        step.started_at = self._clock()
        step.status = InvestigationStepStatus.RUNNING
        self._touch(state)
        trajectory.record(
            TrajectoryEventType.STEP_STARTED,
            step_id=step.step_id,
            details={
                "order": step.order,
                "action": step.action,
                "suggested_tool": step.suggested_tool,
            },
        )
        self._store.save_state(state)

    def _finish_step(
        self,
        state: InvestigationRuntimeState,
        step: InvestigationStep,
        trajectory: TrajectoryRecorder,
        *,
        status: InvestigationStepStatus,
        error: str | None,
        details: dict[str, Any],
    ) -> None:
        step.status = status
        step.completed_at = self._clock()
        step.error = error
        self._touch(state)
        event_type = (
            TrajectoryEventType.STEP_COMPLETED
            if status is InvestigationStepStatus.COMPLETED
            else TrajectoryEventType.STEP_FAILED
        )
        trajectory.record(
            event_type,
            step_id=step.step_id,
            details={"order": step.order, "action": step.action, "error": error, **details},
        )
        self._store.save_state(state)

    def _run_step(
        self,
        state: InvestigationRuntimeState,
        step: InvestigationStep,
        trajectory: TrajectoryRecorder,
    ) -> _StepOutcome:
        """Ask the planner repeatedly until the step becomes terminal."""
        while True:
            context = self._build_context(state, step)
            try:
                decision = self._planner.decide_next_action(context)
            except Exception as exc:  # noqa: BLE001 - planner failures are contained
                return _StepOutcome(
                    status=InvestigationStepStatus.FAILED,
                    stop_reason=StopReason.PLANNER_FAILED,
                    error=f"planner raised {type(exc).__name__}",
                    details={"failure": "planner_exception", "error_type": type(exc).__name__},
                )

            trajectory.record(
                TrajectoryEventType.PLANNER_DECISION,
                step_id=step.step_id,
                details={
                    "action": decision.action.value,
                    "tool_name": decision.tool_name,
                    "rationale": decision.rationale,
                    "arguments": decision.arguments,
                    "remaining_tool_budget": context.remaining_tool_budget,
                    "remaining_step_budget": context.remaining_step_budget,
                },
            )

            if decision.action is PlannerAction.COMPLETE_STEP:
                return _StepOutcome(
                    status=InvestigationStepStatus.COMPLETED,
                    details={"decision": decision.action.value},
                )
            if decision.action is PlannerAction.FAIL_STEP:
                return _StepOutcome(
                    status=InvestigationStepStatus.FAILED,
                    error=decision.rationale,
                    details={"decision": decision.action.value},
                )

            call_outcome = self._execute_planned_tool_call(state, step, decision, trajectory)
            if call_outcome.stop_reason is not None:
                return _StepOutcome(
                    status=InvestigationStepStatus.FAILED,
                    stop_reason=call_outcome.stop_reason,
                    error=call_outcome.error,
                    details=call_outcome.details,
                )
            if not call_outcome.succeeded:
                return _StepOutcome(
                    status=InvestigationStepStatus.FAILED,
                    error=call_outcome.error,
                    details=call_outcome.details,
                )

    def _build_context(
        self, state: InvestigationRuntimeState, step: InvestigationStep
    ) -> PlanningContext:
        calls_in_step = sum(1 for call in state.tool_calls if call.step_id == step.step_id)
        # Steps only run after the runtime stored a plan, so ``state.plan`` is set.
        return PlanningContext(
            alert=state.alert,
            plan=state.plan,
            current_step=step,
            previous_tool_calls=list(state.tool_calls),
            previous_tool_results=list(state.tool_results),
            remaining_tool_budget=max(self._budget.max_tool_calls - state.total_tool_calls, 0),
            remaining_step_budget=max(
                self._budget.max_tool_calls_per_step - calls_in_step, 0
            ),
        )

    # Tool calls --------------------------------------------------------------

    def _execute_planned_tool_call(
        self,
        state: InvestigationRuntimeState,
        step: InvestigationStep,
        decision: PlannerDecision,
        trajectory: TrajectoryRecorder,
    ) -> _CallOutcome:
        """Execute one planned call, retrying with a fresh ToolCall when allowed."""
        attempts = 0
        while True:
            calls_in_step = sum(1 for call in state.tool_calls if call.step_id == step.step_id)
            stop_reason = self._budget.stop_reason_for_tool_call(
                total_tool_calls=state.total_tool_calls, calls_in_step=calls_in_step
            )
            if stop_reason is None:
                stop_reason = self._budget.stop_reason_for_failures(
                    total_tool_failures=state.total_tool_failures
                )
            if stop_reason is not None:
                return _CallOutcome(
                    succeeded=False,
                    stop_reason=stop_reason,
                    error=stop_reason.value,
                    details={
                        "stop_reason": stop_reason.value,
                        "calls_in_step": calls_in_step,
                        "total_tool_calls": state.total_tool_calls,
                        "total_tool_failures": state.total_tool_failures,
                    },
                )

            tool_call = self._create_tool_call(state, step, decision)
            trajectory.record(
                TrajectoryEventType.TOOL_CALL_CREATED,
                step_id=step.step_id,
                tool_call_id=tool_call.tool_call_id,
                details={
                    "tool_name": tool_call.tool_name,
                    "attempt": attempts + 1,
                    "arguments": decision.arguments,
                },
            )
            tool_call.status = ToolCallStatus.RUNNING
            tool_call.started_at = self._clock()
            self._touch(state)
            trajectory.record(
                TrajectoryEventType.TOOL_STARTED,
                step_id=step.step_id,
                tool_call_id=tool_call.tool_call_id,
                details={"tool_name": tool_call.tool_name},
            )

            try:
                tool_result = self._executor.execute(tool_call)
            except Exception as exc:  # noqa: BLE001 - defensive: never leak executor errors
                # The call was dispatched and therefore consumed one attempt: it
                # counts against the call budget exactly like a returned failure,
                # but it produces no ToolResult (none may be fabricated) - only a
                # trajectory event referencing the failed ToolCall.
                attempts += 1
                state.total_tool_calls += 1
                state.total_tool_failures += 1
                self._record_attempt(state, step, attempts)
                tool_call.status = ToolCallStatus.FAILED
                tool_call.completed_at = self._clock()
                self._touch(state)
                trajectory.record(
                    TrajectoryEventType.TOOL_FAILED,
                    step_id=step.step_id,
                    tool_call_id=tool_call.tool_call_id,
                    details={
                        "tool_name": tool_call.tool_name,
                        "failure_kind": EXECUTOR_EXCEPTION_FAILURE_KIND,
                        "attempt": attempts,
                    },
                )
                self._store.save_state(state)
                return _CallOutcome(
                    succeeded=False,
                    stop_reason=StopReason.UNRECOVERABLE_TOOL_ERROR,
                    error=f"tool executor raised {type(exc).__name__}",
                    details={
                        "failure": "executor_exception",
                        "error_type": type(exc).__name__,
                        "tool_name": tool_call.tool_name,
                    },
                )

            tool_call.completed_at = self._clock()
            state.tool_results.append(tool_result)
            state.total_tool_calls += 1
            attempts += 1

            if tool_result.success:
                tool_call.status = ToolCallStatus.SUCCEEDED
                self._record_attempt(state, step, attempts)
                trajectory.record(
                    TrajectoryEventType.TOOL_SUCCEEDED,
                    step_id=step.step_id,
                    tool_call_id=tool_call.tool_call_id,
                    tool_result_id=tool_result.tool_result_id,
                    details={
                        "tool_name": tool_result.tool_name,
                        "latency_ms": tool_result.latency_ms,
                        "attempt": attempts,
                    },
                )
                self._store.save_state(state)
                return _CallOutcome(succeeded=True, details={"attempts": attempts})

            tool_call.status = ToolCallStatus.FAILED
            state.total_tool_failures += 1
            failure_kind = classify_tool_failure(tool_result.error)
            self._record_attempt(state, step, attempts)
            trajectory.record(
                TrajectoryEventType.TOOL_FAILED,
                step_id=step.step_id,
                tool_call_id=tool_call.tool_call_id,
                tool_result_id=tool_result.tool_result_id,
                details={
                    "tool_name": tool_result.tool_name,
                    "failure_kind": failure_kind.value,
                    "error": tool_result.error,
                    "attempt": attempts,
                },
            )

            if self._retry_policy.should_retry(failure_kind, attempts_in_step=attempts):
                trajectory.record(
                    TrajectoryEventType.RETRY_SCHEDULED,
                    step_id=step.step_id,
                    tool_call_id=tool_call.tool_call_id,
                    details={
                        "next_attempt": attempts + 1,
                        "max_attempts_per_step": self._retry_policy.max_attempts_per_step,
                        "failure_kind": failure_kind.value,
                    },
                )
                self._store.save_state(state)
                continue

            self._store.save_state(state)
            if failure_kind is ToolFailureKind.EXECUTION_ERROR:
                return _CallOutcome(
                    succeeded=False,
                    error=f"{tool_result.tool_name} failed after {attempts} attempt(s)",
                    details={"failure_kind": failure_kind.value, "attempts": attempts},
                )
            return _CallOutcome(
                succeeded=False,
                stop_reason=StopReason.UNRECOVERABLE_TOOL_ERROR,
                error=f"unrecoverable tool failure ({failure_kind.value})",
                details={"failure_kind": failure_kind.value, "attempts": attempts},
            )

    def _create_tool_call(
        self,
        state: InvestigationRuntimeState,
        step: InvestigationStep,
        decision: PlannerDecision,
    ) -> ToolCall:
        tool_call = ToolCall(
            tool_call_id=self._id_generator.next_tool_call_id(),
            incident_id=state.incident_id,
            step_id=step.step_id,
            tool_name=decision.tool_name or "",
            arguments=dict(decision.arguments or {}),
            rationale=decision.rationale,
            status=ToolCallStatus.REQUESTED,
            requested_at=self._clock(),
        )
        state.tool_calls.append(tool_call)
        return tool_call

    # Bookkeeping -------------------------------------------------------------

    @staticmethod
    def _record_attempt(
        state: InvestigationRuntimeState, step: InvestigationStep, attempts: int
    ) -> None:
        state.step_attempts[step.step_id] = max(state.step_attempts.get(step.step_id, 0), attempts)

    @staticmethod
    def _stamp_incident_id(plan: InvestigationPlan, incident_id: str) -> InvestigationPlan:
        """Keep ``INC-*`` ownership with the runtime.

        The planner protocol is ``create_plan(alert)`` and therefore cannot know
        the incident id; the runtime stamps its own id onto the plan.
        """
        if plan.incident_id == incident_id:
            return plan
        return plan.model_copy(update={"incident_id": incident_id})

    def _touch(self, state: InvestigationRuntimeState) -> None:
        state.updated_at = self._clock()

    def _terminate_for_stop_reason(
        self,
        state: InvestigationRuntimeState,
        trajectory: TrajectoryRecorder,
        stop_reason: StopReason,
    ) -> InvestigationRun:
        if stop_reason in BUDGET_STOP_REASONS:
            return self._terminate(
                state,
                trajectory,
                status=RuntimeStatus.BUDGET_EXHAUSTED,
                stop_reason=stop_reason,
                event_type=TrajectoryEventType.BUDGET_EXHAUSTED,
                details={
                    "stop_reason": stop_reason.value,
                    "current_step_id": state.current_step_id,
                    "total_tool_calls": state.total_tool_calls,
                    "total_tool_failures": state.total_tool_failures,
                },
            )
        return self._terminate(
            state,
            trajectory,
            status=RuntimeStatus.FAILED,
            stop_reason=stop_reason,
            event_type=TrajectoryEventType.INVESTIGATION_FAILED,
            details={
                "stop_reason": stop_reason.value,
                "current_step_id": state.current_step_id,
                "failure": stop_reason.value,
            },
        )

    def _terminate(
        self,
        state: InvestigationRuntimeState,
        trajectory: TrajectoryRecorder,
        *,
        status: RuntimeStatus,
        stop_reason: StopReason,
        event_type: TrajectoryEventType,
        details: dict[str, Any],
    ) -> InvestigationRun:
        completed_at = self._clock()
        state.status = status
        state.stop_reason = stop_reason
        state.completed_at = completed_at
        state.updated_at = completed_at
        self._store.save_state(state)
        trajectory.record(event_type, details=details)
        return InvestigationRun(
            incident_id=state.incident_id,
            alert=state.alert,
            plan=state.plan,
            tool_calls=list(state.tool_calls),
            tool_results=list(state.tool_results),
            trajectory=trajectory.events,
            status=status,
            stop_reason=stop_reason,
            started_at=state.started_at,
            completed_at=completed_at,
        )
