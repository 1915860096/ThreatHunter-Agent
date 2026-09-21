"""Tests that ground truth stays isolated from the agent-facing loader."""

from __future__ import annotations

import ast
import inspect
import shutil
import textwrap
from pathlib import Path

import pytest
from pydantic import BaseModel

from app.benchmark import (
    BenchmarkLoader,
    DatasetFormatError,
    GroundTruthLoader,
    MissingGroundTruthError,
)
from app.benchmark.loader import EXPECTED_CASE_IDS
from app.benchmark.schemas import (
    CaseMetadata,
    DNSEvent,
    EndpointEvent,
    FileRecord,
    NetworkEvent,
)

EXPECTED_BENCHMARK_LOADER_API = {
    "dataset_root",
    "list_cases",
    "load_attack_techniques",
    "load_case_metadata",
    "load_cti_records",
    "load_dns_events",
    "load_endpoint_events",
    "load_file_records",
    "load_initial_alert",
    "load_ioc_reputation_records",
    "load_network_events",
}


def code_without_docstrings(source: str) -> str:
    """Return ``source`` with every docstring stripped."""
    tree = ast.parse(textwrap.dedent(source))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree)


def test_benchmark_loader_exposes_no_ground_truth_api() -> None:
    assert not hasattr(BenchmarkLoader, "load_ground_truth")
    assert not hasattr(BenchmarkLoader, "load_everything")
    assert not hasattr(BenchmarkLoader, "ground_truth_root")


def test_benchmark_loader_public_api_surface_is_exactly_the_runtime_api() -> None:
    public_api = {name for name in dir(BenchmarkLoader) if not name.startswith("_")}

    assert public_api == EXPECTED_BENCHMARK_LOADER_API


def test_benchmark_loader_method_names_mention_no_answers() -> None:
    public_api = {name for name in dir(BenchmarkLoader) if not name.startswith("_")}

    assert not [name for name in public_api if "ground" in name or "truth" in name]
    assert not [name for name in public_api if "verdict" in name or "expected" in name]


def test_benchmark_loader_implementation_never_touches_ground_truth() -> None:
    code = code_without_docstrings(inspect.getsource(BenchmarkLoader)).lower()

    assert "ground_truth" not in code
    assert "groundtruthloader" not in code
    assert "verdict" not in code
    assert "expected_" not in code


def test_case_metadata_schema_has_no_answer_fields() -> None:
    assert set(CaseMetadata.model_fields) == {
        "case_id",
        "name",
        "description",
        "difficulty",
        "available_sources",
        "initial_alert_id",
    }


def test_ground_truth_loader_is_a_separate_evaluation_loader() -> None:
    truth_loader = GroundTruthLoader()

    assert GroundTruthLoader is not BenchmarkLoader
    assert hasattr(GroundTruthLoader, "load_ground_truth")
    assert hasattr(GroundTruthLoader, "list_ground_truth_cases")
    assert set(truth_loader.list_ground_truth_cases()) == set(EXPECTED_CASE_IDS)


def test_benchmark_loader_works_without_the_ground_truth_directory(dataset_dir: Path) -> None:
    shutil.rmtree(dataset_dir / "ground_truth")
    loader = BenchmarkLoader(dataset_dir)

    assert loader.list_cases() == list(EXPECTED_CASE_IDS)
    assert loader.load_case_metadata("CASE-001").case_id == "CASE-001"
    assert loader.load_initial_alert("CASE-001").alert_id == "ALT-001"
    assert loader.load_endpoint_events("CASE-001")
    assert loader.load_ioc_reputation_records()
    assert loader.load_cti_records()
    assert loader.load_attack_techniques()


def test_benchmark_loader_ignores_broken_ground_truth_files(dataset_dir: Path) -> None:
    (dataset_dir / "ground_truth" / "CASE-001.json").write_text("{", encoding="utf-8")
    loader = BenchmarkLoader(dataset_dir)

    assert loader.list_cases() == list(EXPECTED_CASE_IDS)
    assert loader.load_dns_events("CASE-001")


def test_ground_truth_loader_still_requires_the_ground_truth_directory(dataset_dir: Path) -> None:
    shutil.rmtree(dataset_dir / "ground_truth")
    truth_loader = GroundTruthLoader(dataset_dir)

    with pytest.raises(DatasetFormatError):
        truth_loader.list_ground_truth_cases()
    with pytest.raises(MissingGroundTruthError):
        truth_loader.load_ground_truth("CASE-001")


@pytest.mark.parametrize(
    "schema",
    [
        CaseMetadata,
        EndpointEvent,
        NetworkEvent,
        DNSEvent,
        FileRecord,
    ],
)
def test_agent_facing_schemas_have_no_answer_fields(schema: type[BaseModel]) -> None:
    answer_fields = {
        "verdict",
        "expected_verdict",
        "expected_iocs",
        "expected_techniques",
        "key_evidence",
        "acceptable_evidence",
    }

    assert not answer_fields.intersection(schema.model_fields)
