"""Fixtures for the T04 tool layer tests.

Tests use the shipped T03 dataset unless they need to mutate data, in which case
they work on a temporary copy.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from app.benchmark.loader import DEFAULT_DATASET_ROOT, BenchmarkLoader
from app.schemas.tools import ToolCall
from app.tools import ToolExecutor

CASE_ID = "CASE-001"


@pytest.fixture
def loader() -> BenchmarkLoader:
    """Loader over the shipped benchmark dataset."""
    return BenchmarkLoader()


@pytest.fixture
def executor(loader: BenchmarkLoader) -> ToolExecutor:
    """Executor wired to the shipped benchmark dataset."""
    return ToolExecutor(loader=loader)


@pytest.fixture
def dataset_dir(tmp_path: Path) -> Path:
    """A writable copy of the shipped dataset."""
    target = tmp_path / "datasets"
    shutil.copytree(DEFAULT_DATASET_ROOT, target)
    return target


@pytest.fixture
def read_json() -> Callable[[Path], Any]:
    def _read(path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8"))

    return _read


@pytest.fixture
def write_json() -> Callable[[Path, Any], None]:
    def _write(path: Path, payload: Any) -> None:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return _write


@pytest.fixture
def tool_call() -> Callable[..., ToolCall]:
    """Build a T02 ToolCall for the given tool name and arguments."""

    def _make(
        tool_name: str,
        arguments: dict[str, Any],
        *,
        tool_call_id: str = "TC-001",
    ) -> ToolCall:
        return ToolCall(
            tool_call_id=tool_call_id,
            incident_id="INC-001",
            step_id="STEP-001",
            tool_name=tool_name,
            arguments=arguments,
            status="requested",
            requested_at="2026-03-02T09:20:00Z",
        )

    return _make
