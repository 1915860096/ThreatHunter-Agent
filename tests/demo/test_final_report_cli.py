"""Replay CLI tests (offline, no agent run, no model call)."""

from __future__ import annotations

import ast
import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from app.demo.final_report import main, replay_report
from app.demo.llm_investigation import run_llm_investigation
from app.reports import FinalInvestigationReport

CASE_ID = "CASE-001"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def payload_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("t08-payload")
    result = run_llm_investigation(
        case_id=CASE_ID, mode="scripted", output_dir=directory
    )
    assert result.output_path is not None
    return result.output_path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_replay_writes_both_reports(payload_path: Path, tmp_path: Path) -> None:
    before = digest(payload_path)

    result = replay_report(input_path=payload_path, output_dir=tmp_path)

    assert result.json_path.name == "final-report.json"
    assert result.markdown_path.name == "final-report.md"
    assert result.json_path.is_file() and result.markdown_path.is_file()
    payload = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert FinalInvestigationReport.model_validate(payload) == result.report
    markdown = result.markdown_path.read_text(encoding="utf-8")
    assert "## 3. Verdict and Confidence" in markdown
    assert digest(payload_path) == before  # the input file is never modified


def test_cli_exits_zero_and_prints_a_summary(
    payload_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(
        ["--input", str(payload_path), "--output-dir", str(tmp_path)]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "final report replay" in captured.out
    assert "verdict" in captured.out
    assert "FIND-000001" in captured.out
    assert (tmp_path / "final-report.json").is_file()


def test_cli_reports_a_missing_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["--input", str(tmp_path / "nope.json"), "--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "not found" in captured.out


def test_cli_reports_invalid_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    exit_code = main(["--input", str(broken), "--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "not valid JSON" in captured.out


def test_cli_reports_a_payload_without_sections(
    payload_path: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stripped = tmp_path / "stripped.json"
    stripped.write_text(json.dumps({"incident_id": "INC-000001"}), encoding="utf-8")

    exit_code = main(["--input", str(stripped), "--output-dir", str(tmp_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "missing required section" in captured.out


def test_replay_makes_no_network_request(
    payload_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("replay must not open a network connection")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    result = replay_report(input_path=payload_path, output_dir=tmp_path)

    assert result.report.findings


def test_replay_modules_never_read_ground_truth_or_llm_configuration() -> None:
    modules = [
        PROJECT_ROOT / "app" / "findings" / "contracts.py",
        PROJECT_ROOT / "app" / "findings" / "engine.py",
        PROJECT_ROOT / "app" / "findings" / "index.py",
        PROJECT_ROOT / "app" / "verdict" / "contracts.py",
        PROJECT_ROOT / "app" / "verdict" / "engine.py",
        PROJECT_ROOT / "app" / "reports" / "contracts.py",
        PROJECT_ROOT / "app" / "reports" / "builder.py",
        PROJECT_ROOT / "app" / "reports" / "markdown.py",
        PROJECT_ROOT / "app" / "demo" / "final_report.py",
    ]
    forbidden_names = (
        "expected_verdict",
        "expected_iocs",
        "expected_techniques",
        "key_evidence",
        "acceptable_evidence",
        "expected_investigation",
    )

    for path in modules:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        assert "ground_truth" not in source, path.name
        for field_name in forbidden_names:
            assert field_name not in source, f"{path.name} mentions {field_name}"
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert "ground_truth" not in (node.module or ""), path.name
        if path.name == "final_report.py":
            assert "get_settings" not in source
            assert "OpenAICompatibleLLMClient" not in source
