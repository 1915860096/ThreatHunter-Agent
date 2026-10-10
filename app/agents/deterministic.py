"""Rule-based deterministic planner.

Its purpose is to exercise the orchestration runtime deterministically, not to
be the final security intelligence of the project. Rules are fixed and derived
only from the alert:

1. ``endpoint_activity`` - look up endpoint telemetry by the alerting process
   (falling back to the host), then by the alert event type;
2. ``file_artifact`` - if the command line mentions a file-like token (not the
   alerting process itself), look up that file's telemetry and reputation;
   otherwise the step completes without any tool call;
3. ``network_activity`` - look up network/DNS telemetry by destination (falling
   back to source), then by the alerting process;
4. ``indicator_enrichment`` - look up IOC reputation for the destination and
   source indicators that the alert carries;
5. ``threat_knowledge`` - search CTI by the destination indicator and ATT&CK by
   the alerting process name.

The planner is bound to one benchmark ``case_id`` (a plain identifier: the
planner never touches the dataset) and only ever returns
``PlannerDecision`` values - it cannot execute tools.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

from app.runtime.contracts import PlannerAction, PlannerDecision, PlanningContext
from app.runtime.ids import IdGenerator, SequentialIdGenerator
from app.schemas.alert import SecurityAlert
from app.schemas.investigation import (
    InvestigationPlan,
    InvestigationStep,
    InvestigationStepStatus,
)

#: Plan incident id placeholder: ``INC-*`` is owned by the runtime, which stamps
#: its own id onto the plan returned by :meth:`DeterministicPlanner.create_plan`.
PLACEHOLDER_INCIDENT_ID: Final[str] = "INC-000000"

#: File-like tokens inside a command line (the regex stops at path separators).
FILE_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9_.\-]+\.(?:exe|dll|ps1|ps|js|jse|vbs|bat|cmd|scr|lnk|zip|rar|7z"
    r"|cab|msi|jar|iso|dmp|doc|docx|xls|xlsx|pdf|txt|py|sh)"
)

TOOL_SEARCH_ENDPOINT = "search_endpoint_events"
TOOL_SEARCH_NETWORK = "search_network_activity"
TOOL_LOOKUP_FILE_REPUTATION = "lookup_file_reputation"
TOOL_LOOKUP_IOC_REPUTATION = "lookup_ioc_reputation"
TOOL_SEARCH_CTI = "search_cti"


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def last_file_token(command_line: str | None, process_name: str | None) -> str | None:
    """Return the last file-like token of a command line.

    Tokens equal to the alerting process are ignored when another candidate
    exists, so ``rundll32.exe ... C:\\Windows\\Temp\\lsass.dmp`` yields
    ``lsass.dmp`` while a command line mentioning only its own process falls
    back to that token.
    """
    if not command_line:
        return None
    tokens = FILE_TOKEN_PATTERN.findall(command_line)
    if not tokens:
        return None
    others = [
        token
        for token in tokens
        if process_name is None or token.casefold() != process_name.casefold()
    ]
    return (others or tokens)[-1]


def base_process_name(process_name: str | None) -> str | None:
    """Return a process name without directory or extension."""
    if not process_name:
        return None
    base = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    stem = base.split(".", 1)[0]
    return stem or None


@dataclass(frozen=True)
class PlannedToolCall:
    """One tool invocation the planner intends to request."""

    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _StepTemplate:
    action: str
    rationale: str
    calls: tuple[PlannedToolCall, ...]


class DeterministicPlanner:
    """Deterministic, rule-based :class:`~app.agents.planner.InvestigationPlanner`.

    One instance may serve several runs; planned calls are remembered per step
    id so ``decide_next_action`` can tell how far a step has progressed.
    """

    def __init__(
        self,
        *,
        case_id: str,
        id_generator: IdGenerator | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._case_id = case_id
        self._id_generator = id_generator or SequentialIdGenerator()
        self._clock = clock or _default_clock
        self._planned_calls: dict[str, tuple[PlannedToolCall, ...]] = {}

    @property
    def case_id(self) -> str:
        """Benchmark case this planner queries."""
        return self._case_id

    def create_plan(self, alert: SecurityAlert) -> InvestigationPlan:
        """Build the fixed five-step plan for ``alert``."""
        plan_id = self._id_generator.next_plan_id()
        steps: list[InvestigationStep] = []
        for order, template in enumerate(self._step_templates(alert), start=1):
            step_id = self._id_generator.next_step_id()
            self._planned_calls[step_id] = template.calls
            steps.append(
                InvestigationStep(
                    step_id=step_id,
                    order=order,
                    action=template.action,
                    rationale=template.rationale,
                    suggested_tool=template.calls[0].tool_name if template.calls else None,
                    status=InvestigationStepStatus.PENDING,
                )
            )

        return InvestigationPlan(
            plan_id=plan_id,
            incident_id=PLACEHOLDER_INCIDENT_ID,
            alert_id=alert.alert_id,
            objective=(
                f"Investigate {alert.event_type} alert {alert.alert_id} on "
                f"{alert.host or 'unknown host'}"
            ),
            steps=steps,
            created_at=self._clock(),
        )

    def decide_next_action(self, context: PlanningContext) -> PlannerDecision:
        """Return the next planned call of the step, or ``complete_step``."""
        step = context.current_step
        planned = self._planned_calls.get(step.step_id, ())
        completed = self._completed_call_count(context, step.step_id)

        if completed >= len(planned):
            return PlannerDecision(
                action=PlannerAction.COMPLETE_STEP,
                rationale=(
                    f"{step.action}: all {len(planned)} planned tool call(s) finished"
                ),
            )

        next_call = planned[completed]
        return PlannerDecision(
            action=PlannerAction.CALL_TOOL,
            tool_name=next_call.tool_name,
            arguments=dict(next_call.arguments),
            rationale=(
                f"{step.action}: {next_call.tool_name} "
                f"(planned call {completed + 1} of {len(planned)})"
            ),
        )

    # Templates ---------------------------------------------------------------

    def _step_templates(self, alert: SecurityAlert) -> list[_StepTemplate]:
        return [
            _StepTemplate(
                action="Collect endpoint activity for the alert",
                rationale=(
                    "Establish which endpoint events match the alerting process, host "
                    "and event type before enriching the alert."
                ),
                calls=(
                    PlannedToolCall(TOOL_SEARCH_ENDPOINT, self._identity_arguments(alert)),
                    PlannedToolCall(
                        TOOL_SEARCH_ENDPOINT,
                        {"case_id": self._case_id, "event_types": [alert.event_type]},
                    ),
                ),
            ),
            _StepTemplate(
                action="Check the file artifact referenced by the alert",
                rationale=(
                    "Determine whether a file named in the alert command line was observed "
                    "on disk and whether its hash is known."
                ),
                calls=self._file_calls(alert),
            ),
            _StepTemplate(
                action="Collect network and DNS activity for the alert",
                rationale=(
                    "Correlate the endpoint activity with outbound network and DNS telemetry "
                    "for the alert destination and process."
                ),
                calls=self._network_calls(alert),
            ),
            _StepTemplate(
                action="Enrich the alert indicators with reputation",
                rationale="Look up known reputation for the source and destination indicators.",
                calls=self._indicator_calls(alert),
            ),
            _StepTemplate(
                action="Consult threat knowledge for the alert behaviour",
                rationale=(
                    "Search synthetic CTI records by the destination indicator and ATT&CK "
                    "knowledge by the alerting process."
                ),
                calls=self._knowledge_calls(alert),
            ),
        ]

    def _identity_arguments(self, alert: SecurityAlert) -> dict[str, Any]:
        if alert.process_name:
            return {"case_id": self._case_id, "process_name": alert.process_name}
        if alert.host:
            return {"case_id": self._case_id, "host": alert.host}
        return {"case_id": self._case_id}

    def _file_calls(self, alert: SecurityAlert) -> tuple[PlannedToolCall, ...]:
        token = last_file_token(alert.command_line, alert.process_name)
        if token is None:
            return ()
        return (
            PlannedToolCall(
                TOOL_LOOKUP_FILE_REPUTATION,
                {"case_id": self._case_id, "file_name": token},
            ),
        )

    def _network_calls(self, alert: SecurityAlert) -> tuple[PlannedToolCall, ...]:
        calls = [PlannedToolCall(TOOL_SEARCH_NETWORK, self._destination_arguments(alert))]
        if alert.process_name:
            calls.append(
                PlannedToolCall(
                    TOOL_SEARCH_NETWORK,
                    {"case_id": self._case_id, "process_name": alert.process_name},
                )
            )
        return tuple(calls)

    def _destination_arguments(self, alert: SecurityAlert) -> dict[str, Any]:
        if alert.dst_ip:
            return {"case_id": self._case_id, "dst_ip": alert.dst_ip}
        if alert.src_ip:
            return {"case_id": self._case_id, "src_ip": alert.src_ip}
        return {"case_id": self._case_id}

    def _indicator_calls(self, alert: SecurityAlert) -> tuple[PlannedToolCall, ...]:
        indicators: Sequence[str | None] = (alert.dst_ip, alert.src_ip)
        return tuple(
            PlannedToolCall(TOOL_LOOKUP_IOC_REPUTATION, {"indicator": indicator})
            for indicator in indicators
            if indicator
        )

    def _knowledge_calls(self, alert: SecurityAlert) -> tuple[PlannedToolCall, ...]:
        calls: list[PlannedToolCall] = []
        if alert.dst_ip:
            calls.append(
                PlannedToolCall(TOOL_SEARCH_CTI, {"indicator": alert.dst_ip})
            )
        stem = base_process_name(alert.process_name)
        if stem:
            calls.append(PlannedToolCall(TOOL_SEARCH_CTI, {"query": stem}))
        return tuple(calls)

    # Progress ----------------------------------------------------------------

    @staticmethod
    def _completed_call_count(context: PlanningContext, step_id: str) -> int:
        """Count planned calls of ``step_id`` that already produced a success."""
        call_ids = {
            call.tool_call_id
            for call in context.previous_tool_calls
            if call.step_id == step_id
        }
        return sum(
            1
            for result in context.previous_tool_results
            if result.tool_call_id in call_ids and result.success
        )
