"""Fixtures for benchmark dataset tests.

Dataset tests that need to mutate files work on a temporary copy of the shipped
dataset so the repository data is never modified by a test run.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from app.benchmark.loader import DEFAULT_DATASET_ROOT


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
