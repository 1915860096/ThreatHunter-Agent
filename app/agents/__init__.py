"""Investigation planners (T05).

The planner is the only decision-making component of the orchestration
runtime, and it is deliberately decoupled from it:

* :class:`~app.agents.planner.InvestigationPlanner` is the protocol the runtime
  depends on;
* :class:`~app.agents.deterministic.DeterministicPlanner` is the rule-based
  planner used to exercise orchestration.

A planner returns :class:`~app.runtime.contracts.PlannerDecision` values and
never executes a tool, never imports a dataset loader and never sees ground
truth. LLM- or LangGraph-based planners are future work and are not part of
T05.
"""

from app.agents.deterministic import PLACEHOLDER_INCIDENT_ID, DeterministicPlanner
from app.agents.planner import InvestigationPlanner

__all__ = [
    "PLACEHOLDER_INCIDENT_ID",
    "DeterministicPlanner",
    "InvestigationPlanner",
]
