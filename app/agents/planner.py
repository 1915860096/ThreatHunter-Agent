"""The planner protocol the orchestration runtime depends on.

A planner is a pure decision component: given an alert it produces an
investigation plan, and given a planning context it returns one
``PlannerDecision`` at a time. It never executes tools, never imports
``BenchmarkLoader``, never reads ``datasets`` and never sees ground truth.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.runtime.contracts import PlannerDecision, PlanningContext
from app.schemas.alert import SecurityAlert
from app.schemas.investigation import InvestigationPlan


@runtime_checkable
class InvestigationPlanner(Protocol):
    """Creates plans and decides the next action of a step."""

    def create_plan(self, alert: SecurityAlert) -> InvestigationPlan:
        """Return the investigation plan for ``alert``.

        The returned plan carries a planner-owned ``PLAN-*`` id and
        ``STEP-*`` step ids. ``INC-*`` belongs to the runtime, so the runtime
        stamps its own incident id onto the plan after this call.
        """

    def decide_next_action(self, context: PlanningContext) -> PlannerDecision:
        """Return the next action for ``context.current_step``."""
