"""Read-only Agent Context Builder (T07).

Turns a real T05 :class:`~app.runtime.contracts.PlanningContext` into a small,
JSON-serializable, sanitized :class:`AgentContext` for the model:

* alert facts, current step goal, allowed tools and their argument constraints,
  tool history, remaining budgets, already-queried indicators, recent failures
  and zero-result queries;
* ``ToolResult`` payloads are never forwarded verbatim - each of the five tools
  has its own compact factual view;
* untrusted text (command lines, CTI summaries, errors) is whitespace-collapsed
  and length-limited, so it can only arrive as *data*;
* truncation is deterministic (oldest history first) and always flagged with
  ``truncated=True``; nothing is invented to fill the context.

The builder never sees a loader, a dataset path, an API key or ground truth.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any, Final

from pydantic import BaseModel, Field

from app.runtime.contracts import PlanningContext
from app.tools.contracts import (
    CTISearchInput,
    EndpointSearchInput,
    FileReputationInput,
    IOCReputationInput,
    NetworkSearchInput,
)

MAX_HISTORY_RESULTS: Final[int] = 12
MAX_RECORDS_PER_RESULT: Final[int] = 10
MAX_CONTEXT_CHARACTERS: Final[int] = 20_000
MAX_TEXT_LENGTH: Final[int] = 200
MAX_KNOWN_INDICATORS: Final[int] = 40

TOOL_INPUT_MODELS: Final[dict[str, type[BaseModel]]] = {
    "search_endpoint_events": EndpointSearchInput,
    "search_network_activity": NetworkSearchInput,
    "lookup_file_reputation": FileReputationInput,
    "lookup_ioc_reputation": IOCReputationInput,
    "search_cti": CTISearchInput,
}

TOOL_DESCRIPTIONS: Final[dict[str, str]] = {
    "search_endpoint_events": (
        "Query endpoint telemetry (process, file and authentication events) of this case."
    ),
    "search_network_activity": (
        "Query network flows and DNS records of this case (both collections are returned "
        "separately; filters that do not apply to a collection are ignored for it)."
    ),
    "lookup_file_reputation": (
        "Query file telemetry by sha256, path or file_name and enrich it with known "
        "SHA256 reputation records."
    ),
    "lookup_ioc_reputation": (
        "Look up the exact reputation records of one indicator (found=false means the "
        "indicator is unknown to the knowledge base, which is not a benign assessment)."
    ),
    "search_cti": (
        "Search synthetic CTI records and ATT&CK knowledge entries; results are references, "
        "never confirmation that a technique was used."
    ),
}

INDICATOR_KEYS: Final[tuple[str, ...]] = (
    "src_ip",
    "dst_ip",
    "response",
    "query",
    "sha256",
    "indicator",
    "file_name",
    "process_name",
    "host",
    "user",
)


def sanitize_text(value: Any, *, limit: int = MAX_TEXT_LENGTH) -> str | None:
    """Collapse whitespace, drop control characters and limit the length."""
    if value is None:
        return None
    text = " ".join(str(value).split())
    if not text:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"


def _compact(record: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if value is not None}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class AgentAlertView(BaseModel):
    """Investigation-relevant alert fields."""

    alert_id: str
    timestamp: str
    source: str
    severity: str
    event_type: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    process_name: str | None = None
    command_line: str | None = None


class AgentToolConstraint(BaseModel):
    """Which arguments a tool accepts (derived from the T04 input schemas)."""

    tool_name: str
    description: str
    allowed_arguments: list[str] = Field(default_factory=list)
    required_arguments: list[str] = Field(default_factory=list)


class AgentStepView(BaseModel):
    """Goal and permissions of the current step."""

    step_id: str
    order: int
    action: str
    rationale: str
    allowed_tools: list[str] = Field(default_factory=list)
    tool_constraints: list[AgentToolConstraint] = Field(default_factory=list)


class AgentToolCallView(BaseModel):
    """A tool call the runtime already executed."""

    tool_call_id: str
    step_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: str


class AgentToolResultView(BaseModel):
    """Compact factual view of one tool result (never the raw payload)."""

    tool_result_id: str
    tool_call_id: str
    tool_name: str
    success: bool
    record_count: int = Field(default=0, ge=0)
    zero_result: bool = False
    not_found: bool = False
    truncated: bool = False
    records: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    note: str | None = None


class AgentQueryHistoryEntry(BaseModel):
    """One query the agent already made, with its outcome."""

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    outcome: str
    observed_values: list[str] = Field(default_factory=list)


class AgentContext(BaseModel):
    """Sanitized, size-limited context handed to the model."""

    incident_id: str
    trusted_case_id: str
    alert: AgentAlertView
    current_step: AgentStepView
    remaining_tool_budget: int = Field(ge=0)
    remaining_step_budget: int = Field(ge=0)
    history_tool_calls: list[AgentToolCallView] = Field(default_factory=list)
    history_tool_results: list[AgentToolResultView] = Field(default_factory=list)
    query_history: list[AgentQueryHistoryEntry] = Field(default_factory=list)
    known_indicators: list[str] = Field(default_factory=list)
    recent_failures: list[str] = Field(default_factory=list)
    recent_empty_results: list[str] = Field(default_factory=list)
    truncated: bool = False
    limits: dict[str, int] = Field(default_factory=dict)

    def to_prompt_payload(self) -> dict[str, Any]:
        """Return the JSON-safe payload handed to the model."""
        return json.loads(self.model_dump_json())

    def canonical_json(self) -> str:
        """Return the deterministic serialization used for prompts and hashing."""
        return json.dumps(self.to_prompt_payload(), sort_keys=True, ensure_ascii=False)

    def fingerprint(self) -> str:
        """Stable fingerprint of the sanitized context (safe: no secrets inside)."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()[:16]


class AgentContextBuilder:
    """Builds :class:`AgentContext` values from T05 planning contexts."""

    def __init__(
        self,
        *,
        case_id: str,
        max_history_results: int = MAX_HISTORY_RESULTS,
        max_records_per_result: int = MAX_RECORDS_PER_RESULT,
        max_characters: int = MAX_CONTEXT_CHARACTERS,
    ) -> None:
        self._case_id = case_id
        self._max_history_results = max_history_results
        self._max_records_per_result = max_records_per_result
        self._max_characters = max_characters

    @property
    def case_id(self) -> str:
        """Trusted case id injected into tool arguments."""
        return self._case_id

    def build(
        self, *, planning_context: PlanningContext, allowed_tools: Sequence[str]
    ) -> AgentContext:
        """Return the sanitized context for the current step of ``planning_context``."""
        calls = list(planning_context.previous_tool_calls)
        results = list(planning_context.previous_tool_results)
        history_calls = [self._call_view(call) for call in calls][-self._max_history_results :]
        history_results = [
            self._result_view(result)
            for result in results[-self._max_history_results :]
        ]
        query_history = self._query_history(calls, results)
        known_indicators = self._known_indicators(history_results)
        failures = [
            f"{view.tool_name} failed (result {view.tool_result_id}): {view.error or 'no error'}"
            for view in history_results
            if not view.success
        ]
        empty = [
            f"{view.tool_name} returned no matching records (result {view.tool_result_id})"
            for view in history_results
            if view.success and view.zero_result
        ]

        context = AgentContext(
            incident_id=str(planning_context.plan.incident_id),
            trusted_case_id=self._case_id,
            alert=self._alert_view(planning_context),
            current_step=self._step_view(planning_context, allowed_tools),
            remaining_tool_budget=planning_context.remaining_tool_budget,
            remaining_step_budget=planning_context.remaining_step_budget,
            history_tool_calls=history_calls,
            history_tool_results=history_results,
            query_history=query_history,
            known_indicators=known_indicators,
            recent_failures=failures,
            recent_empty_results=empty,
            limits={
                "max_history_results": self._max_history_results,
                "max_records_per_result": self._max_records_per_result,
                "max_characters": self._max_characters,
                "max_known_indicators": MAX_KNOWN_INDICATORS,
            },
        )
        context.truncated = self._enforce_character_limit(context)
        return context

    # Views -------------------------------------------------------------------

    def _alert_view(self, planning_context: PlanningContext) -> AgentAlertView:
        alert = planning_context.alert
        return AgentAlertView(
            alert_id=alert.alert_id,
            timestamp=alert.timestamp.isoformat(),
            source=alert.source,
            severity=alert.severity.value,
            event_type=alert.event_type,
            host=sanitize_text(alert.host),
            user=sanitize_text(alert.user),
            src_ip=sanitize_text(alert.src_ip),
            dst_ip=sanitize_text(alert.dst_ip),
            process_name=sanitize_text(alert.process_name),
            command_line=sanitize_text(alert.command_line),
        )

    def _step_view(
        self, planning_context: PlanningContext, allowed_tools: Sequence[str]
    ) -> AgentStepView:
        step = planning_context.current_step
        return AgentStepView(
            step_id=step.step_id,
            order=step.order,
            action=sanitize_text(step.action) or step.action,
            rationale=sanitize_text(step.rationale) or step.rationale,
            allowed_tools=sorted(allowed_tools),
            tool_constraints=[
                self._tool_constraint(tool_name) for tool_name in sorted(allowed_tools)
            ],
        )

    @staticmethod
    def _tool_constraint(tool_name: str) -> AgentToolConstraint:
        model = TOOL_INPUT_MODELS[tool_name]
        allowed = sorted(field for field in model.model_fields if field != "case_id")
        required = sorted(
            field
            for field in allowed
            if model.model_fields[field].is_required()
        )
        return AgentToolConstraint(
            tool_name=tool_name,
            description=TOOL_DESCRIPTIONS[tool_name],
            allowed_arguments=allowed,
            required_arguments=required,
        )

    @staticmethod
    def _call_view(call: Any) -> AgentToolCallView:
        arguments = {
            key: sanitize_text(value) if isinstance(value, str) else value
            for key, value in call.arguments.items()
        }
        return AgentToolCallView(
            tool_call_id=call.tool_call_id,
            step_id=call.step_id,
            tool_name=call.tool_name,
            arguments=arguments,
            status=call.status.value,
        )

    def _result_view(self, result: Any) -> AgentToolResultView:
        payload = _as_dict(result.data)
        if not result.success:
            return AgentToolResultView(
                tool_result_id=result.tool_result_id,
                tool_call_id=result.tool_call_id,
                tool_name=result.tool_name,
                success=False,
                error=sanitize_text(result.error),
                note="tool failed: no facts are available from this result",
            )

        summarizer = self._summarizers().get(result.tool_name)
        if summarizer is None:
            return AgentToolResultView(
                tool_result_id=result.tool_result_id,
                tool_call_id=result.tool_call_id,
                tool_name=result.tool_name,
                success=True,
                note="payload shape is not supported by the context builder",
            )
        records, zero_result, not_found, truncated, note = summarizer(payload)
        return AgentToolResultView(
            tool_result_id=result.tool_result_id,
            tool_call_id=result.tool_call_id,
            tool_name=result.tool_name,
            success=True,
            record_count=len(records),
            zero_result=zero_result,
            not_found=not_found,
            truncated=truncated,
            records=records,
            note=note,
        )

    def _summarizers(self) -> dict[str, Any]:
        return {
            "search_endpoint_events": self._summarize_endpoint,
            "search_network_activity": self._summarize_network,
            "lookup_file_reputation": self._summarize_file_reputation,
            "lookup_ioc_reputation": self._summarize_ioc_reputation,
            "search_cti": self._summarize_cti,
        }

    def _limit(self, values: list[Any]) -> tuple[list[Any], bool]:
        if len(values) <= self._max_records_per_result:
            return values, False
        return values[: self._max_records_per_result], True

    # Summarizers -------------------------------------------------------------

    def _summarize_endpoint(
        self, payload: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], bool, bool, bool, str | None]:
        count = payload.get("count")
        records: list[dict[str, Any]] = []
        for raw in _as_list(payload.get("items")):
            if not isinstance(raw, dict):
                continue
            metadata = _as_dict(raw.get("metadata"))
            record = _compact(
                {
                    "event_id": raw.get("event_id"),
                    "timestamp": raw.get("timestamp"),
                    "host": raw.get("host"),
                    "user": raw.get("user"),
                    "event_type": raw.get("event_type"),
                    "process_name": raw.get("process_name"),
                    "parent_process_name": raw.get("parent_process_name"),
                    "pid": raw.get("pid"),
                    "file_path": sanitize_text(raw.get("file_path")),
                    "sha256": raw.get("sha256"),
                    "command_line": sanitize_text(raw.get("command_line")),
                    "source_ip": sanitize_text(metadata.get("source_ip")),
                    "logon_type": metadata.get("logon_type"),
                }
            )
            records.append(record)
        records, truncated = self._limit(records)
        zero_result = count == 0 if isinstance(count, int) else not records
        note = "no matching endpoint events" if zero_result else None
        return records, zero_result, False, truncated or bool(payload.get("truncated")), note

    def _summarize_network(
        self, payload: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], bool, bool, bool, str | None]:
        records: list[dict[str, Any]] = []
        for raw in _as_list(payload.get("network_events")):
            if not isinstance(raw, dict):
                continue
            records.append(
                _compact(
                    {
                        "record_type": "network_flow",
                        "event_id": raw.get("event_id"),
                        "timestamp": raw.get("timestamp"),
                        "src_host": raw.get("src_host"),
                        "src_ip": raw.get("src_ip"),
                        "src_port": raw.get("src_port"),
                        "dst_ip": raw.get("dst_ip"),
                        "dst_port": raw.get("dst_port"),
                        "protocol": raw.get("protocol"),
                        "direction": raw.get("direction"),
                        "bytes_sent": raw.get("bytes_sent"),
                        "bytes_received": raw.get("bytes_received"),
                        "process_name": raw.get("process_name"),
                    }
                )
            )
        for raw in _as_list(payload.get("dns_events")):
            if not isinstance(raw, dict):
                continue
            records.append(
                _compact(
                    {
                        "record_type": "dns_query",
                        "event_id": raw.get("event_id"),
                        "timestamp": raw.get("timestamp"),
                        "host": raw.get("host"),
                        "src_ip": raw.get("src_ip"),
                        "query": raw.get("query"),
                        "query_type": raw.get("record_type"),
                        "response": raw.get("response"),
                        "process_name": raw.get("process_name"),
                    }
                )
            )
        records, truncated = self._limit(records)
        network_count = payload.get("network_count")
        dns_count = payload.get("dns_count")
        zero_result = (network_count == 0) and (dns_count == 0)
        note = "no matching network or DNS records" if zero_result else None
        return records, zero_result, False, truncated, note

    def _summarize_file_reputation(
        self, payload: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], bool, bool, bool, str | None]:
        records: list[dict[str, Any]] = []
        for raw in _as_list(payload.get("files")):
            if not isinstance(raw, dict):
                continue
            records.append(
                _compact(
                    {
                        "record_type": "file",
                        "file_id": raw.get("file_id"),
                        "timestamp": raw.get("timestamp"),
                        "host": raw.get("host"),
                        "path": sanitize_text(raw.get("path")),
                        "file_name": raw.get("file_name"),
                        "sha256": raw.get("sha256"),
                        "size": raw.get("size"),
                        "signed": raw.get("signed"),
                        "signer": sanitize_text(raw.get("signer")),
                        "source_url": sanitize_text(raw.get("source_url")),
                    }
                )
            )
        for raw in _as_list(payload.get("reputations")):
            if not isinstance(raw, dict):
                continue
            records.append(self._reputation_record(raw))
        records, truncated = self._limit(records)
        count = payload.get("count")
        zero_result = count == 0 if isinstance(count, int) else not records
        note = "no matching file telemetry record" if zero_result else None
        if not zero_result and not _as_list(payload.get("reputations")):
            note = "no reputation record known for the matched file hash (unknown, not benign)"
        return records, zero_result, False, truncated, note

    def _summarize_ioc_reputation(
        self, payload: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], bool, bool, bool, str | None]:
        records = [
            self._reputation_record(raw)
            for raw in _as_list(payload.get("records"))
            if isinstance(raw, dict)
        ]
        records, truncated = self._limit(records)
        found = payload.get("found")
        not_found = found is False
        zero_result = not records
        note: str | None = None
        if not_found:
            note = "indicator absent from the knowledge base (unknown, not benign)"
        elif any(record.get("reputation") == "unknown" for record in records):
            note = "reputation is reported as 'unknown'; no assessment is available"
        return records, zero_result, not_found, truncated, note

    def _summarize_cti(
        self, payload: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], bool, bool, bool, str | None]:
        records: list[dict[str, Any]] = []
        for raw in _as_list(payload.get("cti_records")):
            if not isinstance(raw, dict):
                continue
            records.append(
                _compact(
                    {
                        "record_type": "cti_record",
                        "cti_id": raw.get("cti_id"),
                        "title": sanitize_text(raw.get("title")),
                        "summary": sanitize_text(raw.get("summary")),
                        "indicators": _as_list(raw.get("indicators")),
                        "malware_families": _as_list(raw.get("malware_families")),
                        "campaigns": _as_list(raw.get("campaigns")),
                        "technique_ids": _as_list(raw.get("technique_ids")),
                        "source": raw.get("source"),
                        "published_at": raw.get("published_at"),
                    }
                )
            )
        for raw in _as_list(payload.get("attack_techniques")):
            if not isinstance(raw, dict):
                continue
            records.append(
                _compact(
                    {
                        "record_type": "attack_knowledge",
                        "technique_id": raw.get("technique_id"),
                        "name": sanitize_text(raw.get("name")),
                        "tactics": _as_list(raw.get("tactics")),
                        "keywords": _as_list(raw.get("keywords")),
                    }
                )
            )
        records, truncated = self._limit(records)
        zero_result = (payload.get("cti_count") == 0) and (payload.get("technique_count") == 0)
        note = None
        if zero_result:
            note = "no matching CTI record or ATT&CK knowledge entry"
        elif payload.get("cti_count") == 0:
            note = (
                "no CTI record matched; ATT&CK entries are knowledge references, not "
                "confirmed technique usage"
            )
        return records, zero_result, False, truncated, note

    @staticmethod
    def _reputation_record(raw: dict[str, Any]) -> dict[str, Any]:
        return _compact(
            {
                "record_type": "ioc_reputation",
                "indicator": raw.get("indicator"),
                "indicator_type": raw.get("indicator_type"),
                "reputation": raw.get("reputation"),
                "confidence": raw.get("confidence"),
                "source": raw.get("source"),
                "last_seen": raw.get("last_seen"),
            }
        )

    # Derived views -----------------------------------------------------------

    @staticmethod
    def _query_history(calls: Sequence[Any], results: Sequence[Any]) -> list[AgentQueryHistoryEntry]:
        by_call = {result.tool_call_id: result for result in results}
        entries: list[AgentQueryHistoryEntry] = []
        for call in calls:
            result = by_call.get(call.tool_call_id)
            arguments = {
                key: sanitize_text(value) if isinstance(value, str) else value
                for key, value in call.arguments.items()
            }
            values: list[str] = []
            outcome = "no_result_yet"
            if result is not None:
                payload = _as_dict(result.data)
                if not result.success:
                    outcome = "failed"
                elif call.tool_name == "lookup_ioc_reputation" and payload.get("found") is False:
                    outcome = "not_found"
                else:
                    values = _observed_values(payload)
                    outcome = "records" if values else "empty"
            entries.append(
                AgentQueryHistoryEntry(
                    tool_name=call.tool_name,
                    arguments=arguments,
                    outcome=outcome,
                    observed_values=values[:MAX_RECORDS_PER_RESULT],
                )
            )
        return entries

    @staticmethod
    def _known_indicators(results: Sequence[AgentToolResultView]) -> list[str]:
        seen: list[str] = []
        for view in results:
            for record in view.records:
                for key in INDICATOR_KEYS:
                    value = record.get(key)
                    if isinstance(value, str) and value and value not in seen:
                        seen.append(value)
        return sorted(seen)[:MAX_KNOWN_INDICATORS]

    # Truncation --------------------------------------------------------------

    def _enforce_character_limit(self, context: AgentContext) -> bool:
        truncated = False
        while len(context.canonical_json()) > self._max_characters:
            if not self._reduce(context):
                return True
            truncated = True
        return truncated

    @staticmethod
    def _reduce(context: AgentContext) -> bool:
        if context.history_tool_results:
            context.history_tool_results.pop(0)
            return True
        if context.history_tool_calls:
            context.history_tool_calls.pop(0)
            return True
        if context.query_history:
            context.query_history.pop(0)
            return True
        if context.known_indicators:
            context.known_indicators.pop()
            return True
        if context.recent_failures:
            context.recent_failures.pop(0)
            return True
        if context.recent_empty_results:
            context.recent_empty_results.pop(0)
            return True
        return False


def _observed_values(payload: dict[str, Any]) -> list[str]:
    """Collect the investigation-relevant values a payload reported."""
    values: list[str] = []
    collections: list[dict[str, Any]] = []
    for key in ("items", "network_events", "dns_events", "files", "reputations", "records", "cti_records", "attack_techniques"):
        collections.extend(item for item in _as_list(payload.get(key)) if isinstance(item, dict))
    for record in collections:
        for key in INDICATOR_KEYS:
            value = record.get(key)
            if isinstance(value, str) and value and value not in values:
                values.append(value)
    return values
