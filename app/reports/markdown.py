"""Markdown rendering of a final report (T08).

Values that originate in telemetry, file names or threat intelligence are
*untrusted text*: they are whitespace-collapsed, length-limited and escaped so a
log line, file name or CTI summary cannot inject Markdown structure or render as
executable content.
"""

from __future__ import annotations

import re
from typing import Final

from app.reports.contracts import FinalInvestigationReport

MAX_CELL_LENGTH: Final[int] = 160
VERDICT_DISCLAIMER: Final[str] = (
    "This verdict is an evidence-grounded assessment, not a calibrated probability."
)

_MARKDOWN_SPECIALS = re.compile(r"([\\`*_{}\[\]()#!|<>~])")


def escape_untrusted(value: object, *, limit: int = MAX_CELL_LENGTH) -> str:
    """Escape untrusted text for safe Markdown rendering."""
    text = " ".join(str(value).split())
    truncated = len(text) > limit
    body = text[:limit] if truncated else text
    escaped = _MARKDOWN_SPECIALS.sub(r"\\\1", body).replace("&", "&amp;")
    # The truncation marker is ours, not untrusted input, so it stays readable.
    return escaped + ("...[truncated]" if truncated else "")


def _code(value: object) -> str:
    text = " ".join(str(value).split()).replace("`", "'")
    return f"`{text}`"


def render_markdown_report(report: FinalInvestigationReport) -> str:
    """Render the nine report sections as Markdown."""
    lines: list[str] = []
    lines.append(f"# ThreatHunter Investigation Report {_code(report.report_id)}")
    lines.append("")
    lines.append(f"> {VERDICT_DISCLAIMER}")
    lines.append("")

    lines.append("## 1. Incident Overview")
    lines.append("")
    lines.append(f"- **Incident:** {_code(report.incident_id)}")
    lines.append(f"- **Case:** {_code(report.case_id)}")
    lines.append(f"- **Alert:** {escape_untrusted(report.alert_summary)}")
    lines.append("")

    lines.append("## 2. Investigation Outcome")
    lines.append("")
    lines.append(f"- **Status:** {_code(report.investigation_status.value)}")
    lines.append(f"- **Stop reason:** {_code(report.stop_reason.value)}")
    lines.append(f"- **Evidence items indexed:** {len(report.evidence_index)}")
    lines.append(f"- **Findings:** {len(report.findings)}")
    lines.append(f"- **Generated at:** {_code(report.generated_at.isoformat())}")
    lines.append("")

    lines.append("## 3. Verdict and Confidence")
    lines.append("")
    lines.append(f"- **Disposition:** {_code(report.verdict.disposition.value)}")
    lines.append(f"- **Confidence level:** {_code(report.verdict.confidence_level.value)}")
    lines.append(f"- **Rule:** {_code(report.verdict.rule_id)}")
    lines.append(
        f"- **Rationale:** {escape_untrusted(report.verdict.rationale, limit=1200)}"
    )
    if report.verdict.supporting_finding_ids:
        lines.append(
            "- **Supporting findings:** "
            + ", ".join(_code(item) for item in report.verdict.supporting_finding_ids)
        )
    if report.verdict.counter_evidence_ids:
        lines.append(
            "- **Counter evidence:** "
            + ", ".join(_code(item) for item in report.verdict.counter_evidence_ids)
        )
    lines.append("")

    lines.append("## 4. Key Findings")
    lines.append("")
    if not report.findings:
        lines.append("_No finding reached the reporting threshold for this investigation._")
        lines.append("")
    for finding in report.findings:
        lines.append(f"### {_code(finding.finding_id)} {escape_untrusted(finding.title)}")
        lines.append("")
        lines.append(
            f"- **Type:** {_code(finding.finding_type.value)} | "
            f"**Severity:** {_code(finding.severity.value)} | "
            f"**Support:** {_code(finding.support_level.value)} | "
            f"**Rule:** {_code(finding.rule_id)}"
        )
        lines.append(
            f"- **Description:** {escape_untrusted(finding.description, limit=1200)}"
        )
        lines.append(
            "- **Evidence:** " + ", ".join(_code(item) for item in finding.evidence_ids)
        )
        if finding.related_indicators:
            lines.append(
                "- **Related indicators:** "
                + ", ".join(
                    _code(escape_untrusted(item, limit=60))
                    for item in finding.related_indicators
                )
            )
        for limitation in finding.limitations:
            lines.append(f"- **Limitation:** {escape_untrusted(limitation, limit=400)}")
        lines.append("")

    lines.append("## 5. Evidence References")
    lines.append("")
    lines.append("| Evidence | Type | Summary | ToolCall | ToolResult | Raw reference |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for entry in report.evidence_index:
        lines.append(
            "| "
            + " | ".join(
                (
                    _code(entry.evidence_id),
                    _code(entry.evidence_type.value),
                    escape_untrusted(entry.summary, limit=120),
                    _code(entry.tool_call_id),
                    _code(entry.tool_result_id),
                    _code(entry.raw_ref),
                )
            )
            + " |"
        )
    lines.append("")

    lines.append("## 6. Investigation Observations")
    lines.append("")
    if not report.observations:
        lines.append("_No observation was produced._")
        lines.append("")
    for observation in report.observations:
        lines.append(
            f"- **[{escape_untrusted(observation.category.value, limit=40)}] "
            f"{escape_untrusted(observation.title)}** - "
            f"{escape_untrusted(observation.description, limit=600)} "
            f"(evidence: {', '.join(_code(item) for item in observation.evidence_ids)})"
        )
    lines.append("")

    lines.append("## 7. Information Gaps")
    lines.append("")
    if not report.information_gaps:
        lines.append("_No information gap was recorded._")
        lines.append("")
    for gap in report.information_gaps:
        lines.append(f"- {escape_untrusted(gap, limit=600)}")
    lines.append("")

    lines.append("## 8. Limitations")
    lines.append("")
    for limitation in report.limitations:
        lines.append(f"- {escape_untrusted(limitation, limit=600)}")
    lines.append("")

    lines.append("## 9. Methodology and Audit Trail")
    lines.append("")
    for item in report.methodology:
        lines.append(f"- {escape_untrusted(item, limit=800)}")
    lines.append("")
    if report.trace_refs:
        lines.append("| Decision | Step | Action | Tool | Validation | ToolCall | Mode |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for ref in report.trace_refs:
            lines.append(
                "| "
                + " | ".join(
                    (
                        _code(ref.decision_id),
                        _code(ref.step_id),
                        _code(ref.action),
                        _code(ref.selected_tool or "-"),
                        _code(ref.validation_status),
                        _code(ref.tool_call_id or "-"),
                        _code(ref.mode or "-"),
                    )
                )
                + " |"
            )
        lines.append("")
    else:
        lines.append("_No agent decision trace was supplied with this payload._")
        lines.append("")
    lines.append(f"> {VERDICT_DISCLAIMER}")
    lines.append("")
    return "\n".join(lines)
