"""``python -m app.demo.investigation --case CASE-001``.

The demo runs the T6 closed loop:

1. load the case alert with the existing ``BenchmarkLoader`` (agent-visible
   input only - ground truth is never read);
2. run the T05 runtime with the deterministic planner and the T04 executor;
3. extract evidence with the deterministic extractor;
4. build the deterministic summary;
5. print a concise summary and write machine-readable JSON
   (``investigation_run``, ``evidence_extraction``, ``investigation_summary``).
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from app.agents import DeterministicPlanner
from app.benchmark.loader import BenchmarkError, BenchmarkLoader
from app.evidence import DeterministicEvidenceExtractor, EvidenceExtractionResult
from app.reporting import DeterministicSummaryBuilder, InvestigationSummary
from app.runtime import InvestigationRuntime, SequentialIdGenerator
from app.runtime.contracts import InvestigationRun
from app.tools import ToolExecutor

DEFAULT_CASE_ID: Final[str] = "CASE-001"
DEFAULT_OUTPUT_DIR: Final[Path] = Path("outputs") / "demo"


@dataclass(frozen=True)
class InvestigationDemoResult:
    """Everything one demo run produced."""

    case_id: str
    run: InvestigationRun
    extraction: EvidenceExtractionResult
    summary: InvestigationSummary
    output_path: Path | None = None

    def to_payload(self) -> dict[str, Any]:
        """Return the JSON-ready payload written by the demo.

        ``model_dump_json`` is re-parsed so the payload is guaranteed to be
        plain JSON (no ``datetime``, ``enum`` or model objects).
        """
        return {
            "case_id": self.case_id,
            "incident_id": self.run.incident_id,
            "investigation_run": json.loads(self.run.model_dump_json()),
            "evidence_extraction": json.loads(self.extraction.model_dump_json()),
            "investigation_summary": json.loads(self.summary.model_dump_json()),
        }


def run_investigation_demo(
    *,
    case_id: str = DEFAULT_CASE_ID,
    output_dir: Path | None = DEFAULT_OUTPUT_DIR,
) -> InvestigationDemoResult:
    """Run the closed loop for ``case_id`` and optionally write its JSON output."""
    loader = BenchmarkLoader()
    alert = loader.load_initial_alert(case_id)

    runtime = InvestigationRuntime(
        DeterministicPlanner(case_id=case_id, id_generator=SequentialIdGenerator()),
        executor=ToolExecutor(loader=loader),
        id_generator=SequentialIdGenerator(),
    )
    run = runtime.run(alert)

    extraction = DeterministicEvidenceExtractor(case_id=case_id).extract(run)
    summary = DeterministicSummaryBuilder().build(run, extraction)
    result = InvestigationDemoResult(
        case_id=case_id, run=run, extraction=extraction, summary=summary
    )

    if output_dir is not None:
        result = InvestigationDemoResult(
            case_id=case_id,
            run=run,
            extraction=extraction,
            summary=summary,
            output_path=write_demo_output(result, output_dir),
        )
    return result


def write_demo_output(result: InvestigationDemoResult, output_dir: Path) -> Path:
    """Write ``<case>-<incident>-investigation.json`` and return its path."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{result.case_id}-{result.run.incident_id}-investigation.json"
    path.write_text(
        json.dumps(result.to_payload(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def render_console_summary(result: InvestigationDemoResult) -> str:
    """Return a concise human-readable summary of one demo run."""
    run, extraction, summary = result.run, result.extraction, result.summary
    category_counts: dict[str, int] = {}
    for observation in summary.observations:
        category_counts[observation.category.value] = (
            category_counts.get(observation.category.value, 0) + 1
        )
    lines = [
        f"ThreatHunter investigation demo - {result.case_id}",
        f"  incident              : {run.incident_id}",
        f"  investigation status  : {run.status.value} (stop reason: {run.stop_reason.value})",
        f"  tool calls / results  : {len(run.tool_calls)} / {len(run.tool_results)}",
        (
            f"  evidence              : {extraction.evidence_count} after dedup "
            f"({extraction.candidate_count} raw record hits, "
            f"{extraction.duplicate_hit_count} duplicate hits, "
            f"{extraction.source_reference_count} source references)"
        ),
        f"  evidence by type      : {_format_counts(extraction.evidence_type_counts)}",
        (f"  observations          : {summary.observation_count} ({_format_counts(category_counts)})"),
        f"  information gaps      : {summary.gap_count}",
        f"  limitations           : {len(summary.limitations)}",
    ]
    if extraction.extraction_warnings:
        lines.append(f"  extraction warnings   : {len(extraction.extraction_warnings)}")
    if summary.unlinked_knowledge_evidence_ids:
        lines.append(
            "  unlinked knowledge    : "
            f"{len(summary.unlinked_knowledge_evidence_ids)} reference(s) without a case link"
        )
    if result.output_path is not None:
        lines.append(f"  JSON output           : {result.output_path}")
    return "\n".join(lines)


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{name}={counts[name]}" for name in sorted(counts))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.demo.investigation",
        description=(
            "Run the deterministic investigation closed loop for one benchmark case "
            "and write the run, the extracted evidence and the summary as JSON."
        ),
    )
    parser.add_argument(
        "--case",
        default=DEFAULT_CASE_ID,
        help=f"benchmark case id to investigate (default: {DEFAULT_CASE_ID})",
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
        result = run_investigation_demo(
            case_id=args.case, output_dir=Path(args.output_dir)
        )
    except BenchmarkError as exc:
        print(f"error: {exc}")
        return 2

    print(render_console_summary(result))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
