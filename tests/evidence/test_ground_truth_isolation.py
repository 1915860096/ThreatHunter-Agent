"""T06 must never read evaluation answers."""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

import pytest

from app.agents import DeterministicPlanner
from app.benchmark import BenchmarkLoader
from app.evidence import DeterministicEvidenceExtractor
from app.reporting import DeterministicSummaryBuilder
from app.runtime import InvestigationRuntime, SequentialIdGenerator
from app.tools import ToolExecutor
from tests.runtime.conftest import TickingClock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
T06_DIRECTORIES = (
    PROJECT_ROOT / "app" / "evidence",
    PROJECT_ROOT / "app" / "reporting",
    PROJECT_ROOT / "app" / "demo",
)

FORBIDDEN_IMPORTS = {
    "GroundTruthLoader",
    "CaseGroundTruth",
    "GroundTruthIOC",
    "GroundTruthTechnique",
    "ExpectedInvestigation",
}

GROUND_TRUTH_FIELD_NAMES = (
    "expected_verdict",
    "expected_iocs",
    "expected_techniques",
    "key_evidence",
    "acceptable_evidence",
    "expected_investigation",
)

CASE_ID = "CASE-001"


def source_paths() -> list[Path]:
    paths: list[Path] = []
    for directory in T06_DIRECTORIES:
        paths.extend(sorted(directory.glob("*.py")))
    return paths


def imported_names(path: Path) -> tuple[set[str], list[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.append(node.module or "")
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return names, modules


def test_t06_modules_are_discovered() -> None:
    assert len(source_paths()) >= 8


@pytest.mark.parametrize("directory", T06_DIRECTORIES, ids=lambda path: path.name)
def test_no_ground_truth_imports(directory: Path) -> None:
    for path in sorted(directory.glob("*.py")):
        names, modules = imported_names(path)

        assert not names & FORBIDDEN_IMPORTS, path.name
        assert not [module for module in modules if "ground_truth" in module], path.name


@pytest.mark.parametrize("directory", T06_DIRECTORIES, ids=lambda path: path.name)
def test_no_ground_truth_names_or_paths(directory: Path) -> None:
    for path in sorted(directory.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        assert "ground_truth" not in source, path.name
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert "GroundTruth" not in node.id, path.name
            elif isinstance(node, ast.Attribute):
                assert "GroundTruth" not in node.attr, path.name


@pytest.mark.parametrize("directory", T06_DIRECTORIES, ids=lambda path: path.name)
def test_no_ground_truth_field_names(directory: Path) -> None:
    for path in sorted(directory.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for field_name in GROUND_TRUTH_FIELD_NAMES:
            assert field_name not in source, f"{path.name} mentions {field_name}"


@pytest.fixture
def dataset_dir(tmp_path: Path) -> Path:
    target = tmp_path / "datasets"
    shutil.copytree(BenchmarkLoader().dataset_root, target)
    return target


def run_full_pipeline(loader: BenchmarkLoader, case_id: str = CASE_ID) -> tuple[object, object, object]:
    clock = TickingClock()
    run = InvestigationRuntime(
        DeterministicPlanner(case_id=case_id, id_generator=SequentialIdGenerator(), clock=clock),
        executor=ToolExecutor(loader=loader, clock=clock),
        id_generator=SequentialIdGenerator(),
        clock=clock,
    ).run(loader.load_initial_alert(case_id))
    extraction = DeterministicEvidenceExtractor(case_id=case_id).extract(run)
    summary = DeterministicSummaryBuilder().build(run, extraction)
    return run, extraction, summary


def test_pipeline_completes_without_the_ground_truth_directory(dataset_dir: Path) -> None:
    shutil.rmtree(dataset_dir / "ground_truth")
    loader = BenchmarkLoader(dataset_dir)

    run, extraction, summary = run_full_pipeline(loader)

    assert run.status.value == "completed"
    assert extraction.evidence_count > 0
    assert summary.evidence_count == extraction.evidence_count


def test_pipeline_ignores_corrupted_ground_truth_files(dataset_dir: Path) -> None:
    for case_path in sorted((dataset_dir / "ground_truth").glob("*.json")):
        case_path.write_text("{", encoding="utf-8")
    loader = BenchmarkLoader(dataset_dir)

    run, extraction, summary = run_full_pipeline(loader)

    assert summary.observation_count > 0
    dumped = summary.model_dump_json()
    for field_name in GROUND_TRUTH_FIELD_NAMES:
        assert field_name not in dumped


def test_extraction_and_summary_contain_no_answer_fields(dataset_dir: Path) -> None:
    loader = BenchmarkLoader(dataset_dir)
    _, extraction, summary = run_full_pipeline(loader)

    combined = extraction.model_dump_json() + summary.model_dump_json()

    assert '"verdict"' not in combined
    assert "evd-" not in combined.lower()
    for field_name in GROUND_TRUTH_FIELD_NAMES:
        assert field_name not in combined
