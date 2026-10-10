"""The tool layer must never be able to read evaluation answers."""

from __future__ import annotations

import ast
import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from app.benchmark.loader import BenchmarkLoader
from app.schemas.tools import ToolCall
from app.tools import (
    CTISearchInput,
    EndpointSearchInput,
    FileReputationInput,
    IOCReputationInput,
    NetworkSearchInput,
    ToolExecutor,
    lookup_file_reputation,
    lookup_ioc_reputation,
    search_cti,
    search_endpoint_events,
    search_network_activity,
)

APP_TOOLS_DIR = Path(__file__).resolve().parents[2] / "app" / "tools"

FORBIDDEN_NAMES = {
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


def tool_source_paths() -> list[Path]:
    return sorted(APP_TOOLS_DIR.glob("*.py"))


def test_app_tools_directory_is_discovered() -> None:
    assert tool_source_paths(), "app/tools must contain python modules"


def test_tools_never_import_ground_truth_objects() -> None:
    for path in tool_source_paths():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported: set[str] = set()
        modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                modules.append(node.module or "")
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)

        assert not imported.intersection(FORBIDDEN_NAMES), path.name
        assert not [module for module in modules if "ground_truth" in module], path.name


def test_tools_reference_no_ground_truth_names_or_paths() -> None:
    for path in tool_source_paths():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        assert "ground_truth" not in source, path.name
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                assert "GroundTruth" not in node.id, path.name
            elif isinstance(node, ast.Attribute):
                assert "GroundTruth" not in node.attr, path.name


def test_tools_never_reference_ground_truth_field_names() -> None:
    for path in tool_source_paths():
        source = path.read_text(encoding="utf-8")
        for field_name in GROUND_TRUTH_FIELD_NAMES:
            assert field_name not in source, f"{path.name} mentions {field_name}"


def test_tool_payloads_expose_no_ground_truth_fields() -> None:
    payload = search_endpoint_events(EndpointSearchInput(case_id="CASE-001"))
    dumped = json.dumps(payload.model_dump(mode="json"))

    for field_name in GROUND_TRUTH_FIELD_NAMES:
        assert field_name not in dumped


def test_benchmark_loader_used_by_tools_has_no_ground_truth_api() -> None:
    loader = BenchmarkLoader()

    assert not hasattr(loader, "load_ground_truth")
    assert not hasattr(loader, "load_everything")
    assert not hasattr(loader, "ground_truth_root")
    assert not [name for name in dir(loader) if "truth" in name.lower()]


def test_all_tools_work_without_the_ground_truth_directory(dataset_dir: Path) -> None:
    shutil.rmtree(dataset_dir / "ground_truth")
    loader = BenchmarkLoader(dataset_dir)

    assert search_endpoint_events(EndpointSearchInput(case_id="CASE-001"), loader).count > 0
    assert (
        search_network_activity(NetworkSearchInput(case_id="CASE-001"), loader).network_count > 0
    )
    assert (
        lookup_file_reputation(
            FileReputationInput(case_id="CASE-001", file_name="update.ps1"), loader
        ).count
        == 1
    )
    assert lookup_ioc_reputation(
        IOCReputationInput(indicator="sync-update.example.net"), loader
    ).found
    assert search_cti(CTISearchInput(query="certutil"), loader).cti_count == 1


def test_executor_works_without_the_ground_truth_directory(
    dataset_dir: Path, tool_call: Callable[..., ToolCall]
) -> None:
    shutil.rmtree(dataset_dir / "ground_truth")
    executor = ToolExecutor(loader=BenchmarkLoader(dataset_dir))

    result = executor.execute(tool_call("search_cti", {"query": "certutil"}))

    assert result.success is True
    assert result.data is not None
    assert result.data["cti_count"] == 1


@pytest.mark.parametrize("case_id", ["CASE-001", "CASE-008"])
def test_broken_ground_truth_files_do_not_affect_tools(
    dataset_dir: Path, case_id: str
) -> None:
    (dataset_dir / "ground_truth" / f"{case_id}.json").write_text("{", encoding="utf-8")
    loader = BenchmarkLoader(dataset_dir)

    assert search_endpoint_events(EndpointSearchInput(case_id=case_id), loader).count > 0
    assert lookup_ioc_reputation(
        IOCReputationInput(indicator="sync-update.example.net"), loader
    ).found
