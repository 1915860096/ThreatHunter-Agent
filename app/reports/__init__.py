"""Final investigation reports (T08).

``app.reports`` assembles the audit artefact that closes the pipeline:

    InvestigationRun + EvidenceExtractionResult + InvestigationSummary
    + SecurityFinding[] + InvestigationVerdict
    -> FinalInvestigationReport -> JSON / Markdown

The report is deterministic (no wall clock, no model call, no ground truth) and
keeps the full audit chain finding -> evidence -> ToolCall/ToolResult ->
raw record.
"""

from app.reports.builder import (
    FinalReportBuilder,
    ReportPayloadError,
    build_report_from_payload,
)
from app.reports.contracts import (
    EvidenceIndexEntry,
    FinalInvestigationReport,
    TraceRef,
)
from app.reports.markdown import escape_untrusted, render_markdown_report

__all__ = [
    "EvidenceIndexEntry",
    "FinalInvestigationReport",
    "FinalReportBuilder",
    "ReportPayloadError",
    "TraceRef",
    "build_report_from_payload",
    "escape_untrusted",
    "render_markdown_report",
]
