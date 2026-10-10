"""Tests for the end-to-end demonstration entry point."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.demo.investigation import (
    DEFAULT_CASE_ID,
    DEFAULT_OUTPUT_DIR,
    InvestigationDemoResult,
    main,
    render_console_summary,
    run_investigation_demo,
)
from app.evidence import EvidenceExtractionResult
from app.reporting import InvestigationSummary
from app.runtime.contracts import InvestigationRun


@pytest.fixture
def demo_result(tmp_path: Path) -> InvestigationDemoResult:
    return run_investigation_demo(case_id=DEFAULT_CASE_ID, output_dir=tmp_path)


def test_demo_runs_the_whole_closed_loop(demo_result: InvestigationDemoResult) -> None:
    run = demo_result.run

    assert run.status.value == "completed"
    assert run.incident_id == "INC-000001"
    assert len(run.tool_calls) == len(run.tool_results) == 9
    assert demo_result.extraction.incident_id == run.incident_id
    assert demo_result.extraction.evidence_count > 0
    assert demo_result.summary.evidence_count == demo_result.extraction.evidence_count


def test_demo_writes_machine_readable_json(
    demo_result: InvestigationDemoResult, tmp_path: Path
) -> None:
    assert demo_result.output_path is not None
    path = demo_result.output_path
    assert path.parent == tmp_path
    assert path.name == "CASE-001-INC-000001-investigation.json"

    payload = json.loads(path.read_text(encoding="utf-8"))

    assert sorted(payload) == [
        "case_id",
        "evidence_extraction",
        "incident_id",
        "investigation_run",
        "investigation_summary",
    ]
    # Both a standard JSON parser and Pydantic can read the file back.
    run = InvestigationRun.model_validate(payload["investigation_run"])
    extraction = EvidenceExtractionResult.model_validate(payload["evidence_extraction"])
    summary = InvestigationSummary.model_validate(payload["investigation_summary"])
    assert extraction.incident_id == run.incident_id == summary.incident_id


def test_demo_output_contains_no_ground_truth(
    demo_result: InvestigationDemoResult,
) -> None:
    assert demo_result.output_path is not None
    text = demo_result.output_path.read_text(encoding="utf-8")

    for field_name in (
        "expected_verdict",
        "expected_iocs",
        "expected_techniques",
        "key_evidence",
        "acceptable_evidence",
        "expected_investigation",
        "ground_truth",
    ):
        assert field_name not in text
    assert '"verdict"' not in text


def test_cli_main_prints_summary_and_returns_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["--case", "CASE-001", "--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "ThreatHunter investigation demo - CASE-001" in captured.out
    assert "incident" in captured.out
    assert "INC-000001" in captured.out
    assert "evidence" in captured.out
    assert "information gaps" in captured.out
    assert (tmp_path / "CASE-001-INC-000001-investigation.json").is_file()


def test_cli_main_reports_unknown_cases_without_crashing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["--case", "CASE-999", "--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out.startswith("error:")
    assert "CASE-999" in captured.out
    assert list(tmp_path.glob("*.json")) == []


def test_demo_can_run_without_writing_output() -> None:
    result = run_investigation_demo(case_id=DEFAULT_CASE_ID, output_dir=None)

    assert result.output_path is None
    assert result.summary.evidence_count > 0


def test_demo_works_for_another_case(tmp_path: Path) -> None:
    result = run_investigation_demo(case_id="CASE-002", output_dir=tmp_path)

    assert result.case_id == "CASE-002"
    assert result.summary.incident_id == result.run.incident_id
    assert result.extraction.case_id == "CASE-002"
    file_evidence = [
        item
        for item in result.extraction.evidence
        if item.content.get("file_name") == "lsass.dmp"
    ]
    assert file_evidence
    assert result.output_path is not None
    assert result.output_path.name.startswith("CASE-002-INC-")


def test_business_output_is_reproducible() -> None:
    first = run_investigation_demo(case_id=DEFAULT_CASE_ID, output_dir=None)
    second = run_investigation_demo(case_id=DEFAULT_CASE_ID, output_dir=None)

    def business_view(result: InvestigationDemoResult) -> dict[str, object]:
        return {
            "evidence": [
                (
                    item.evidence_id,
                    item.evidence_type.value,
                    item.summary,
                    item.content,
                    item.tags,
                    item.provenance.raw_ref,
                    item.provenance.tool_call_id,
                    item.provenance.tool_result_id,
                )
                for item in result.extraction.evidence
            ],
            "observations": [
                (
                    observation.category.value,
                    observation.title,
                    observation.description,
                    observation.evidence_ids,
                )
                for observation in result.summary.observations
            ],
            "gaps": list(result.summary.information_gaps),
            "unlinked": list(result.summary.unlinked_knowledge_evidence_ids),
            "tool_names": [call.tool_name for call in result.run.tool_calls],
            "status": (result.run.status.value, result.run.stop_reason.value),
        }

    assert business_view(first) == business_view(second)


def test_console_summary_mentions_the_important_numbers(
    demo_result: InvestigationDemoResult,
) -> None:
    text = render_console_summary(demo_result)

    assert "completed (stop reason: completed)" in text
    assert "9 / 9" in text
    assert "after dedup" in text
    assert "unlinked knowledge" in text
    assert "limitations" in text


def test_default_output_directory_is_ignored_by_git() -> None:
    assert DEFAULT_OUTPUT_DIR == Path("outputs") / "demo"

    gitignore = Path(__file__).resolve().parents[2] / ".gitignore"
    assert "outputs/" in gitignore.read_text(encoding="utf-8")
