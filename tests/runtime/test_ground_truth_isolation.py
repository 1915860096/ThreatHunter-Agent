"""The runtime and planners must never be able to read evaluation answers."""

from __future__ import annotations

import ast
import shutil
from pathlib import Path
from typing import Any

import pytest

from app.agents import DeterministicPlanner
from app.benchmark import BenchmarkLoader
from app.runtime import InvestigationRuntime, RuntimeStatus, SequentialIdGenerator
from app.tools import ToolExecutor
from tests.runtime.conftest import CASE_ID, TickingClock

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = PROJECT_ROOT / "app" / "runtime"
AGENTS_DIR = PROJECT_ROOT / "app" / "agents"

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


def source_paths(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.py"))


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


def test_directories_are_discovered() -> None:
    assert source_paths(RUNTIME_DIR)
    assert source_paths(AGENTS_DIR)


@pytest.mark.parametrize("directory", [RUNTIME_DIR, AGENTS_DIR])
def test_no_ground_truth_imports(directory: Path) -> None:
    for path in source_paths(directory):
        names, modules = imported_names(path)

        assert not names & FORBIDDEN_IMPORTS, path.name
        assert not [module for module in modules if "ground_truth" in module], path.name


@pytest.mark.parametrize("directory", [RUNTIME_DIR, AGENTS_DIR])
def test_no_ground_truth_names_or_paths(directory: Path) -> None:
    for path in source_paths(directory):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        assert "ground_truth" not in source, path.name
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert "GroundTruth" not in node.id, path.name
            elif isinstance(node, ast.Attribute):
                assert "GroundTruth" not in node.attr, path.name


@pytest.mark.parametrize("directory", [RUNTIME_DIR, AGENTS_DIR])
def test_no_ground_truth_field_names(directory: Path) -> None:
    for path in source_paths(directory):
        source = path.read_text(encoding="utf-8")
        for field_name in GROUND_TRUTH_FIELD_NAMES:
            assert field_name not in source, f"{path.name} mentions {field_name}"


def test_planner_never_imports_a_dataset_loader() -> None:
    for path in source_paths(AGENTS_DIR):
        _, modules = imported_names(path)

        assert not [module for module in modules if "benchmark" in module], path.name
        assert not [module for module in modules if "datasets" in module], path.name
        assert "app.tools" not in modules, path.name


def test_runtime_never_imports_a_dataset_loader() -> None:
    for path in source_paths(RUNTIME_DIR):
        _, modules = imported_names(path)

        assert not [module for module in modules if "benchmark" in module], path.name
        assert not [module for module in modules if "datasets" in module], path.name


def test_planner_has_no_dataset_attributes() -> None:
    planner = DeterministicPlanner(case_id=CASE_ID)
    public_names = [name for name in dir(planner) if not name.startswith("_")]

    assert public_names == ["case_id", "create_plan", "decide_next_action"]


def build_runtime(loader: BenchmarkLoader) -> InvestigationRuntime:
    clock = TickingClock()
    return InvestigationRuntime(
        DeterministicPlanner(
            case_id=CASE_ID, id_generator=SequentialIdGenerator(), clock=clock
        ),
        executor=ToolExecutor(loader=loader, clock=clock),
        id_generator=SequentialIdGenerator(),
        clock=clock,
    )


def test_runtime_completes_without_the_ground_truth_directory(dataset_dir: Path) -> None:
    shutil.rmtree(dataset_dir / "ground_truth")
    loader = BenchmarkLoader(dataset_dir)

    run = build_runtime(loader).run(loader.load_initial_alert(CASE_ID))

    assert run.status is RuntimeStatus.COMPLETED
    assert len(run.tool_calls) > 0


def test_runtime_ignores_corrupted_ground_truth_files(dataset_dir: Path) -> None:
    for case_path in sorted((dataset_dir / "ground_truth").glob("*.json")):
        case_path.write_text("{", encoding="utf-8")
    loader = BenchmarkLoader(dataset_dir)

    run = build_runtime(loader).run(loader.load_initial_alert(CASE_ID))

    assert run.status is RuntimeStatus.COMPLETED
    assert "verdict" not in run.model_dump_json()


def test_run_contains_no_ground_truth_fields(dataset_dir: Path) -> None:
    loader = BenchmarkLoader(dataset_dir)
    run = build_runtime(loader).run(loader.load_initial_alert(CASE_ID))
    dumped = run.model_dump_json()

    for field_name in GROUND_TRUTH_FIELD_NAMES:
        assert field_name not in dumped
