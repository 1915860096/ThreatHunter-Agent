"""``python -m app.demo.final_report --input <investigation.json>``.

Offline Replay: read an existing T06/T07 investigation payload, rebuild the T08
findings, verdict and final report, and write ``final-report.json`` plus
``final-report.md``.

Replay never re-runs the agent, never calls a tool, never contacts a model, never
needs an API key and never reads ground truth. The input file is only read.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from app.reports import (
    FinalInvestigationReport,
    ReportPayloadError,
    build_report_from_payload,
    render_markdown_report,
)

DEFAULT_OUTPUT_DIR: Final[Path] = Path("outputs") / "reports"
REPORT_JSON_NAME: Final[str] = "final-report.json"
REPORT_MARKDOWN_NAME: Final[str] = "final-report.md"


@dataclass(frozen=True)
class ReplayResult:
    """Result of one offline replay."""

    input_path: Path
    report: FinalInvestigationReport
    json_path: Path
    markdown_path: Path


def load_investigation_payload(input_path: Path) -> dict[str, Any]:
    """Read one investigation JSON file (never modifies it)."""
    path = Path(input_path)
    if not path.is_file():
        raise ReportPayloadError(f"input file not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReportPayloadError(f"input file is not valid JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ReportPayloadError("input JSON must be an object with investigation sections")
    return payload


def replay_report(
    *,
    input_path: Path,
    output_dir: Path | None = DEFAULT_OUTPUT_DIR,
) -> ReplayResult:
    """Rebuild the final report of one stored investigation."""
    path = Path(input_path)
    payload = load_investigation_payload(path)
    report = build_report_from_payload(payload)

    json_path = Path(output_dir or DEFAULT_OUTPUT_DIR) / REPORT_JSON_NAME
    markdown_path = Path(output_dir or DEFAULT_OUTPUT_DIR) / REPORT_MARKDOWN_NAME
    directory = json_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
    return ReplayResult(
        input_path=path, report=report, json_path=json_path, markdown_path=markdown_path
    )


def render_console_summary(result: ReplayResult) -> str:
    """Return a concise human-readable summary of one replay."""
    report = result.report
    lines = [
        f"ThreatHunter final report replay - {report.case_id}",
        f"  input                 : {result.input_path}",
        f"  incident              : {report.incident_id}",
        f"  investigation status  : {report.investigation_status.value} "
        f"(stop reason: {report.stop_reason.value})",
        f"  findings              : {len(report.findings)}",
        f"  verdict               : {report.verdict.disposition.value} "
        f"(confidence: {report.verdict.confidence_level.value}, rule: {report.verdict.rule_id})",
        f"  evidence indexed      : {len(report.evidence_index)}",
        f"  information gaps      : {len(report.information_gaps)}",
        f"  JSON report           : {result.json_path}",
        f"  Markdown report       : {result.markdown_path}",
    ]
    for finding in report.findings:
        lines.append(
            f"    {finding.finding_id} {finding.finding_type.value} "
            f"severity={finding.severity.value} support={finding.support_level.value} "
            f"evidence={len(finding.evidence_ids)} rule={finding.rule_id}"
        )
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.demo.final_report",
        description=(
            "Rebuild the T08 findings, verdict and final report from an existing "
            "investigation JSON (offline: no agent run, no tools, no model call)."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        help="path to an existing investigation JSON produced by the T06/T07 demo CLIs",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help=f"directory for final-report.json and final-report.md (default: {DEFAULT_OUTPUT_DIR})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    args = _build_parser().parse_args(argv)
    try:
        result = replay_report(
            input_path=Path(args.input), output_dir=Path(args.output_dir)
        )
    except ReportPayloadError as exc:
        print(f"error: ReportPayloadError: {exc}")
        return 2

    print(render_console_summary(result))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
