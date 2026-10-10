"""``python -m app.demo.llm_investigation --case CASE-001 --mode scripted``.

The demo drives the same closed loop as T06, but the decisions come from an
`LLMPlanner`:

Alert -> LLMPlanner -> T05 Runtime -> T04 ToolExecutor -> ToolResult
      -> AgentContextBuilder -> next LLMPlanner decision
      -> T06 EvidenceExtractor -> InvestigationSummary

``scripted`` mode uses a deterministic rule-based client: it reads the sanitized
``AgentContext`` and changes its next query based on what previous tool results
contained. It is an engineering integration check, **not** a language model and
**not** evidence of model reasoning quality.

``live`` mode uses the real OpenAI-compatible client and fails loudly when the
LLM configuration is missing - it never falls back to scripted.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final

from app.agents import (
    AgentDecisionTrace,
    AgentDecisionTraceRecorder,
    LLMBudget,
    LLMClient,
    LLMClientConfig,
    LLMCompletion,
    LLMConfigurationError,
    LLMPlanner,
    OpenAICompatibleLLMClient,
    correlate_trace_with_run,
)
from app.agents.deterministic import last_file_token
from app.benchmark.loader import BenchmarkError, BenchmarkLoader
from app.core.config import get_settings
from app.evidence import DeterministicEvidenceExtractor, EvidenceExtractionResult
from app.reporting import DeterministicSummaryBuilder, InvestigationSummary
from app.runtime import InvestigationRuntime, SequentialIdGenerator
from app.runtime.contracts import InvestigationRun
from app.tools import ToolExecutor

DEFAULT_CASE_ID: Final[str] = "CASE-001"
DEFAULT_OUTPUT_DIR: Final[Path] = Path("outputs") / "demo"
SCRIPTED_MODE: Final[str] = "scripted"
LIVE_MODE: Final[str] = "live"

TOOL_SEARCH_ENDPOINT = "search_endpoint_events"
TOOL_SEARCH_NETWORK = "search_network_activity"
TOOL_LOOKUP_FILE_REPUTATION = "lookup_file_reputation"
TOOL_LOOKUP_IOC_REPUTATION = "lookup_ioc_reputation"
TOOL_SEARCH_CTI = "search_cti"

MAX_CALLS_PER_STEP: Final[int] = 2


class RuleBasedScriptedLLMClient:
    """Deterministic, context-dependent stand-in for a model (scripted mode).

    Rules (documented, fixed):

    * endpoint step - query by the alerting process, then by the alert event type
      only if the first query returned records; otherwise complete the step;
    * file step - query the file-like token of the alert command line, once;
    * network step - query the alert destination, then query the *observed*
      process from the returned flows (no records -> complete the step);
    * indicator step - query up to two indicators observed in earlier results,
      preferring destinations; no observed indicator -> complete the step;
    * knowledge step - use the indicator that came back with a reputation record,
      then (only if that search returned CTI records) query the returned campaign.

    Every decision therefore depends on previous tool results.
    """

    name: Final[str] = "rule-based-scripted"
    mode: Final[str] = SCRIPTED_MODE

    def __init__(self) -> None:
        self.requests = 0

    def complete(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        model: str | None = None,
        timeout_seconds: float | None = None,
    ) -> LLMCompletion:
        """Return the rule-based decision for the context in ``messages``."""
        self.requests += 1
        context = _context_from_messages(messages)
        decision = self._decide(context)
        return LLMCompletion(
            content=json.dumps(decision, sort_keys=True),
            model=model or self.name,
            prompt_tokens=None,
            completion_tokens=None,
        )

    # Rules -------------------------------------------------------------------

    def _decide(self, context: dict[str, Any]) -> dict[str, Any]:
        step = context["current_step"]
        order = int(step["order"])
        step_id = step["step_id"]
        calls = [call for call in context["history_tool_calls"] if call["step_id"] == step_id]
        view = {
            "step_records": _records_of_step(context, step_id),
            "history_records": [
                record
                for result in context["history_tool_results"]
                for record in (result.get("records") or [])
            ],
        }
        if len(calls) >= MAX_CALLS_PER_STEP:
            return _complete("step call limit reached")

        if len(calls) >= MAX_CALLS_PER_STEP:
            return _complete("step call limit reached")

        handler = {
            1: self._endpoint_decision,
            2: self._file_decision,
            3: self._network_decision,
            4: self._indicator_decision,
            5: self._knowledge_decision,
        }.get(order)
        if handler is None:
            return _complete("unknown step order")
        return handler(context, calls, view)

    @staticmethod
    def _endpoint_decision(
        context: dict[str, Any], calls: list[dict[str, Any]], view: dict[str, Any]
    ) -> dict[str, Any]:
        alert = context["alert"]
        if not calls:
            if alert.get("process_name"):
                return _call(
                    TOOL_SEARCH_ENDPOINT,
                    {"process_name": alert["process_name"]},
                    "query endpoint events for the alerting process",
                )
            if alert.get("host"):
                return _call(
                    TOOL_SEARCH_ENDPOINT,
                    {"host": alert["host"]},
                    "query endpoint events for the alerting host",
                )
            return _complete("no identity filter available for endpoint telemetry")
        if view["step_records"]:
            return _call(
                TOOL_SEARCH_ENDPOINT,
                {"event_types": [alert["event_type"]]},
                "the process query returned events; check the alert event type as well",
            )
        return _complete("the endpoint query returned no records")

    @staticmethod
    def _file_decision(
        context: dict[str, Any], calls: list[dict[str, Any]], view: dict[str, Any]
    ) -> dict[str, Any]:
        alert = context["alert"]
        token = last_file_token(alert.get("command_line"), alert.get("process_name"))
        if not token:
            return _complete("the alert command line names no file artifact")
        if calls:
            return _complete("the referenced file was already looked up")
        return _call(
            TOOL_LOOKUP_FILE_REPUTATION,
            {"file_name": token},
            f"look up the file artifact {token} named in the alert command line",
        )

    @staticmethod
    def _network_decision(
        context: dict[str, Any], calls: list[dict[str, Any]], view: dict[str, Any]
    ) -> dict[str, Any]:
        alert = context["alert"]
        if not calls:
            destination = alert.get("dst_ip")
            if destination:
                return _call(
                    TOOL_SEARCH_NETWORK,
                    {"dst_ip": destination},
                    f"query network and DNS telemetry for the alert destination {destination}",
                )
            if alert.get("src_ip"):
                return _call(
                    TOOL_SEARCH_NETWORK,
                    {"src_ip": alert["src_ip"]},
                    "query network and DNS telemetry for the alert source",
                )
            return _complete("the alert carries no network indicator")
        step_records = view["step_records"]
        if not step_records:
            return _complete("the destination query returned no flow or DNS records")
        processes = [
            record.get("process_name")
            for record in step_records
            if record.get("record_type") == "network_flow" and record.get("process_name")
        ]
        if processes:
            return _call(
                TOOL_SEARCH_NETWORK,
                {"process_name": processes[0]},
                f"the destination query returned flows from {processes[0]}; query that process",
            )
        return _complete("no process could be derived from the returned records")

    @staticmethod
    def _indicator_decision(
        context: dict[str, Any], calls: list[dict[str, Any]], view: dict[str, Any]
    ) -> dict[str, Any]:
        observed = _observed_indicators(view["history_records"])
        if not observed:
            return _complete("no indicator was observed in earlier results")
        if len(calls) >= len(observed):
            return _complete("every observed indicator has been looked up")
        return _call(
            TOOL_LOOKUP_IOC_REPUTATION,
            {"indicator": observed[len(calls)]},
            f"look up the reputation of the observed indicator {observed[len(calls)]}",
        )

    @staticmethod
    def _knowledge_decision(
        context: dict[str, Any], calls: list[dict[str, Any]], view: dict[str, Any]
    ) -> dict[str, Any]:
        records = view["history_records"]
        known = [
            record.get("indicator")
            for record in records
            if record.get("record_type") == "ioc_reputation" and record.get("indicator")
        ]
        if not calls:
            if not known:
                return _complete("no indicator with reputation data is available")
            return _call(
                TOOL_SEARCH_CTI,
                {"indicator": known[0]},
                f"search threat knowledge for the indicator {known[0]}",
            )
        campaigns = [
            campaign
            for record in records
            if record.get("record_type") == "cti_record"
            for campaign in (record.get("campaigns") or [])
        ]
        if campaigns:
            return _call(
                TOOL_SEARCH_CTI,
                {"query": campaigns[0]},
                f"the indicator search returned reports from campaign {campaigns[0]}; "
                "query that campaign",
            )
        return _complete("the indicator search returned no CTI records")


def _call(tool_name: str, arguments: dict[str, Any], rationale: str) -> dict[str, Any]:
    return {
        "action": "call_tool",
        "tool_name": tool_name,
        "arguments": arguments,
        "rationale": rationale,
    }


def _complete(rationale: str) -> dict[str, Any]:
    return {"action": "complete_step", "tool_name": None, "arguments": None, "rationale": rationale}


def _context_from_messages(messages: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    for message in reversed(list(messages)):
        if message.get("role") == "user":
            try:
                payload = json.loads(str(message.get("content", "")))
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and "current_step" in payload:
                return payload
    raise ValueError("no agent context found in the messages")


def _records_of_step(context: dict[str, Any], step_id: str) -> list[dict[str, Any]]:
    call_ids = {
        call["tool_call_id"] for call in context["history_tool_calls"] if call["step_id"] == step_id
    }
    records: list[dict[str, Any]] = []
    for view in context["history_tool_results"]:
        if view["tool_call_id"] in call_ids:
            records.extend(view.get("records") or [])
    return records


def _observed_indicators(records: Sequence[dict[str, Any]]) -> list[str]:
    """Observed destinations first, then sources, de-duplicated and ordered."""
    destinations = [record["dst_ip"] for record in records if record.get("dst_ip")]
    sources = [record["src_ip"] for record in records if record.get("src_ip")]
    ordered: list[str] = []
    for value in destinations + sources:
        if value not in ordered:
            ordered.append(value)
    return ordered


@dataclass(frozen=True)
class LLMInvestigationResult:
    """Everything one model-driven demo run produced."""

    case_id: str
    mode: str
    client_name: str
    run: InvestigationRun
    extraction: EvidenceExtractionResult
    summary: InvestigationSummary
    decisions: list[AgentDecisionTrace]
    llm_requests_used: int
    llm_request_budget: int
    output_path: Path | None = None

    def to_payload(self) -> dict[str, Any]:
        """Return the JSON-ready payload written by the demo."""
        return {
            "case_id": self.case_id,
            "incident_id": self.run.incident_id,
            "agent_mode": self.mode,
            "llm_client": self.client_name,
            "llm_usage": {
                "requests_used": self.llm_requests_used,
                "request_budget": self.llm_request_budget,
                "note": (
                    "scripted mode uses a deterministic rule-based client, not a language "
                    "model and not a measure of model capability"
                    if self.mode == SCRIPTED_MODE
                    else "live mode uses the configured OpenAI-compatible endpoint"
                ),
            },
            "investigation_run": json.loads(self.run.model_dump_json()),
            "agent_decision_trace": [
                json.loads(entry.model_dump_json()) for entry in self.decisions
            ],
            "evidence_extraction": json.loads(self.extraction.model_dump_json()),
            "investigation_summary": json.loads(self.summary.model_dump_json()),
        }


def build_llm_planner(
    *, case_id: str, mode: str, client: LLMClient, budget: LLMBudget | None = None
) -> LLMPlanner:
    """Build an :class:`LLMPlanner` for one run (shared by demo and tests)."""
    if mode not in (SCRIPTED_MODE, LIVE_MODE):
        raise ValueError(f"unknown mode {mode!r}; expected 'scripted' or 'live'")
    budget = budget or LLMBudget()
    model_name = getattr(client, "name", None) or getattr(client, "model", None)
    return LLMPlanner(
        case_id=case_id,
        client=client,
        budget=budget,
        model=model_name,
        mode=mode,
        recorder=AgentDecisionTraceRecorder(mode=mode, model=model_name),
    )


def run_llm_investigation(
    *,
    case_id: str = DEFAULT_CASE_ID,
    mode: str = SCRIPTED_MODE,
    output_dir: Path | None = DEFAULT_OUTPUT_DIR,
    budget: LLMBudget | None = None,
) -> LLMInvestigationResult:
    """Run the model-driven closed loop for ``case_id``."""
    effective_budget = budget or LLMBudget()
    if mode == SCRIPTED_MODE:
        client: LLMClient = RuleBasedScriptedLLMClient()
    elif mode == LIVE_MODE:
        # No silent fallback: a missing configuration fails loudly.
        client = OpenAICompatibleLLMClient(LLMClientConfig.from_settings(get_settings()))
    else:
        raise ValueError(f"unknown mode {mode!r}; expected 'scripted' or 'live'")

    loader = BenchmarkLoader()
    alert = loader.load_initial_alert(case_id)
    planner = build_llm_planner(
        case_id=case_id, mode=mode, client=client, budget=effective_budget
    )
    runtime = InvestigationRuntime(
        planner,
        executor=ToolExecutor(loader=loader),
        id_generator=SequentialIdGenerator(),
    )
    run = runtime.run(alert)

    extraction = DeterministicEvidenceExtractor(case_id=case_id).extract(run)
    summary = DeterministicSummaryBuilder().build(run, extraction)
    result = LLMInvestigationResult(
        case_id=case_id,
        mode=mode,
        client_name=getattr(client, "name", None) or getattr(client, "model", "unknown"),
        run=run,
        extraction=extraction,
        summary=summary,
        decisions=correlate_trace_with_run(planner.decisions, run),
        llm_requests_used=planner.requests_used,
        llm_request_budget=effective_budget.max_llm_requests_per_run,
    )
    if output_dir is not None:
        result = replace(
            result, output_path=write_llm_demo_output(result, output_dir)
        )
    return result


def write_llm_demo_output(result: LLMInvestigationResult, output_dir: Path) -> Path:
    """Write ``<case>-<incident>-llm-investigation.json`` and return its path."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{result.case_id}-{result.run.incident_id}-llm-investigation.json"
    path.write_text(
        json.dumps(result.to_payload(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def render_console_summary(result: LLMInvestigationResult) -> str:
    """Return a concise human-readable summary of one model-driven run."""
    run, extraction, summary = result.run, result.extraction, result.summary
    lines = [
        f"ThreatHunter LLM investigation demo - {result.case_id} ({result.mode} mode)",
        f"  agent client          : {result.client_name}",
        f"  incident              : {run.incident_id}",
        f"  investigation status  : {run.status.value} (stop reason: {run.stop_reason.value})",
        (
            f"  model requests        : {result.llm_requests_used} / "
            f"{result.llm_request_budget}"
        ),
        f"  tool calls / results  : {len(run.tool_calls)} / {len(run.tool_results)}",
        f"  evidence              : {extraction.evidence_count} (deduplicated from "
        f"{extraction.candidate_count} raw record hits)",
        f"  observations / gaps   : {summary.observation_count} / {summary.gap_count}",
        "  decisions:",
    ]
    for entry in result.decisions:
        target = entry.selected_tool or "-"
        lines.append(
            f"    {entry.decision_id} step={entry.step_id} action={entry.action} "
            f"tool={target} status={entry.validation_status} "
            f"repair={entry.repair_attempt} tc={entry.tool_call_id or '-'}"
        )
    if result.mode == SCRIPTED_MODE:
        lines.append(
            "  note                  : scripted mode uses a deterministic rule-based client; "
            "it validates the integration, not model reasoning"
        )
    if result.output_path is not None:
        lines.append(f"  JSON output           : {result.output_path}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.demo.llm_investigation",
        description=(
            "Run the LLM-planned investigation loop (scripted rule-based client or live "
            "OpenAI-compatible endpoint) and write run, decisions, evidence and summary JSON."
        ),
    )
    parser.add_argument("--case", default=DEFAULT_CASE_ID, help="benchmark case id")
    parser.add_argument(
        "--mode",
        default=SCRIPTED_MODE,
        choices=(SCRIPTED_MODE, LIVE_MODE),
        help="scripted = deterministic rule-based client, live = configured LLM endpoint",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"directory for the JSON output (default: {DEFAULT_OUTPUT_DIR})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    args = _build_parser().parse_args(argv)
    try:
        result = run_llm_investigation(
            case_id=args.case, mode=args.mode, output_dir=Path(args.output_dir)
        )
    except (BenchmarkError, LLMConfigurationError) as exc:
        print(f"error: {type(exc).__name__}: {exc}")
        return 2

    print(render_console_summary(result))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
