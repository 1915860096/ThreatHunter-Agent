"""Lightweight agent decision trace (T07).

Every model request produces one immutable trace entry. Entries carry a stable
``decision_id`` plus the step id, the sanitized context fingerprint and (after
correlation with the run) the resulting ``tool_call_id``, so a decision can be
joined to the T05 trajectory without relying on timestamps.

Never recorded: API keys, raw prompts, full logs, unsanitized exception
messages, ground truth or raw model responses.
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from app.agents.context import sanitize_text
from app.runtime.contracts import InvestigationRun
from app.schemas.common import NonEmptyStr, StepId, ToolCallId

DECISION_ID_PREFIX: Final[str] = "AGD"
MAX_RATIONALE_LENGTH: Final[int] = 300

VALIDATION_ACCEPTED: Final[str] = "accepted"
VALIDATION_REPAIRED: Final[str] = "repaired_accepted"
VALIDATION_REJECTED: Final[str] = "rejected"
VALIDATION_FALLBACK: Final[str] = "fallback"


class AgentDecisionTrace(BaseModel):
    """One sanitized decision record."""

    model_config = ConfigDict(extra="forbid")

    decision_id: NonEmptyStr
    request_sequence: int = Field(default=0, ge=0)
    step_id: StepId | None = None
    context_fingerprint: NonEmptyStr
    action: NonEmptyStr
    selected_tool: str | None = None
    validation_status: str
    repair_attempt: int = Field(default=0, ge=0)
    latency_ms: int | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    failure_kind: str | None = None
    rationale: str = ""
    model: str | None = None
    mode: str = "live"
    model_parameters: dict[str, Any] = Field(default_factory=dict)
    tool_call_id: ToolCallId | None = None


class AgentDecisionTraceRecorder:
    """Sequentially records decision traces for one run."""

    def __init__(
        self, *, mode: str = "live", model: str | None = None
    ) -> None:
        self._mode = mode
        self._model = model
        self._sequence = 0
        self._entries: list[AgentDecisionTrace] = []

    @property
    def mode(self) -> str:
        """Run mode the traces belong to (``scripted`` or ``live``)."""
        return self._mode

    @property
    def entries(self) -> list[AgentDecisionTrace]:
        """Recorded traces, in order."""
        return list(self._entries)

    def record(
        self,
        *,
        context_fingerprint: str,
        action: str,
        validation_status: str,
        step_id: str | None = None,
        selected_tool: str | None = None,
        request_sequence: int = 0,
        repair_attempt: int = 0,
        latency_ms: int | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        failure_kind: str | None = None,
        rationale: str = "",
        model_parameters: dict[str, Any] | None = None,
    ) -> AgentDecisionTrace:
        """Append one trace entry and return it."""
        self._sequence += 1
        entry = AgentDecisionTrace(
            decision_id=f"{DECISION_ID_PREFIX}-{self._sequence:06d}",
            request_sequence=request_sequence,
            step_id=step_id,
            context_fingerprint=context_fingerprint,
            action=action,
            selected_tool=selected_tool,
            validation_status=validation_status,
            repair_attempt=repair_attempt,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            failure_kind=failure_kind,
            rationale=sanitize_text(rationale, limit=MAX_RATIONALE_LENGTH) or "",
            model=self._model,
            mode=self._mode,
            model_parameters=dict(model_parameters or {}),
        )
        self._entries.append(entry)
        return entry


def correlate_trace_with_run(
    decisions: list[AgentDecisionTrace], run: InvestigationRun
) -> list[AgentDecisionTrace]:
    """Attach the resulting ``tool_call_id`` to each accepted ``call_tool`` trace.

    Pairing is deterministic: inside one step, the n-th accepted decision for a
    tool maps to the n-th ToolCall of that step and tool. Timestamps are never
    used.
    """
    pending: dict[tuple[str, str], list[str]] = {}
    for call in run.tool_calls:
        pending.setdefault((call.step_id, call.tool_name), []).append(call.tool_call_id)
    consumed: dict[tuple[str, str], int] = {}

    correlated: list[AgentDecisionTrace] = []
    for entry in decisions:
        if (
            entry.action != "call_tool"
            or entry.step_id is None
            or not entry.selected_tool
        ):
            correlated.append(entry)
            continue
        key = (entry.step_id, entry.selected_tool)
        available = pending.get(key, [])
        index = consumed.get(key, 0)
        if index < len(available):
            consumed[key] = index + 1
            correlated.append(entry.model_copy(update={"tool_call_id": available[index]}))
        else:
            correlated.append(entry)
    return correlated
