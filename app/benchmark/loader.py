"""Dataset loaders and cross-file validation for the T03 benchmark.

Two loaders with strictly separated responsibilities:

* :class:`BenchmarkLoader` is the agent/runtime-facing loader. It reads
  ``datasets/cases`` and ``datasets/knowledge`` only, and it deliberately
  exposes no ground-truth API - no ``load_ground_truth``, no "load everything"
  shortcut - so runtime code cannot leak evaluation answers.
* :class:`GroundTruthLoader` is evaluation-only and reads
  ``datasets/ground_truth``.

:func:`validate_dataset` walks the whole dataset and reports cross-file
problems: missing cases, alerts that disagree with their metadata, unknown
evidence references, unsupported ground-truth IOCs or techniques, duplicate
telemetry IDs and a wrong verdict distribution.

Paths are resolved from the repository root, never from the current working
directory.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
from typing import Any, Callable, Final, TypeVar

from pydantic import BaseModel, ValidationError

from app.benchmark.schemas import (
    AttackTechniqueRecord,
    CaseGroundTruth,
    CaseMetadata,
    CTIRecord,
    DNSEvent,
    EndpointEvent,
    FileRecord,
    IOCReputationRecord,
    NetworkEvent,
)
from app.schemas import SecurityAlert

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_ROOT: Final[Path] = PROJECT_ROOT / "datasets"

CASES_DIRECTORY: Final[str] = "cases"
KNOWLEDGE_DIRECTORY: Final[str] = "knowledge"
GROUND_TRUTH_DIRECTORY: Final[str] = "ground_truth"
TELEMETRY_DIRECTORY: Final[str] = "telemetry"

CASE_METADATA_FILE: Final[str] = "case_metadata.json"
INITIAL_ALERT_FILE: Final[str] = "initial_alert.json"
ENDPOINT_EVENTS_FILE: Final[str] = "endpoint_events.json"
NETWORK_EVENTS_FILE: Final[str] = "network_events.json"
DNS_EVENTS_FILE: Final[str] = "dns_events.json"
FILES_FILE: Final[str] = "files.json"

IOC_REPUTATION_FILE: Final[str] = "ioc_reputation.json"
CTI_RECORDS_FILE: Final[str] = "cti_records.json"
ATTACK_TECHNIQUES_FILE: Final[str] = "attack_techniques.json"

EXPECTED_CASE_IDS: Final[tuple[str, ...]] = tuple(
    f"CASE-{index:03d}" for index in range(1, 9)
)
EXPECTED_VERDICT_DISTRIBUTION: Final[dict[str, int]] = {
    "malicious": 4,
    "benign": 2,
    "suspicious": 1,
    "inconclusive": 1,
}

CASE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^CASE-[0-9]{3}$")

ModelT = TypeVar("ModelT", bound=BaseModel)


class BenchmarkError(Exception):
    """Base class for benchmark dataset access errors."""


class CaseNotFoundError(BenchmarkError):
    """Raised when a case id is unknown to the dataset."""


class MissingGroundTruthError(BenchmarkError):
    """Raised when ground truth for a case does not exist."""


class DatasetFormatError(BenchmarkError):
    """Raised when a dataset file is missing, malformed or schema-invalid."""


def _resolve_dataset_root(dataset_root: Path | str | None) -> Path:
    return Path(dataset_root) if dataset_root is not None else DEFAULT_DATASET_ROOT


def _require_case_id(case_id: str) -> str:
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.fullmatch(case_id):
        raise CaseNotFoundError(
            f"invalid case id {case_id!r}: expected an id such as 'CASE-001'"
        )
    return case_id


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise DatasetFormatError(f"dataset file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DatasetFormatError(f"malformed JSON in {path}: {exc}") from exc


def _parse(payload: Any, schema: type[ModelT], path: Path) -> ModelT:
    try:
        return schema.model_validate(payload)
    except ValidationError as exc:
        raise DatasetFormatError(
            f"{path} does not satisfy {schema.__name__}: {exc}"
        ) from exc


def _parse_list(payload: Any, schema: type[ModelT], path: Path) -> list[ModelT]:
    if not isinstance(payload, list):
        raise DatasetFormatError(f"{path} must contain a JSON array of records")
    return [_parse(entry, schema, path) for entry in payload]


class BenchmarkLoader:
    """Agent/runtime-facing access to cases and shared knowledge.

    The class intentionally provides no way to read ``datasets/ground_truth``;
    evaluation answers are only reachable through :class:`GroundTruthLoader`.
    """

    def __init__(self, dataset_root: Path | str | None = None) -> None:
        self._root = _resolve_dataset_root(dataset_root)

    @property
    def dataset_root(self) -> Path:
        """Root directory of the dataset (holds cases, knowledge, ground truth)."""
        return self._root

    # Cases -------------------------------------------------------------------

    def list_cases(self) -> list[str]:
        """Return the available case ids, sorted."""
        cases_directory = self._root / CASES_DIRECTORY
        if not cases_directory.is_dir():
            raise DatasetFormatError(f"dataset cases directory not found: {cases_directory}")
        return sorted(entry.name for entry in cases_directory.iterdir() if entry.is_dir())

    def load_case_metadata(self, case_id: str) -> CaseMetadata:
        """Load the agent-visible metadata of one case."""
        return self._load_case_artifact(case_id, CASE_METADATA_FILE, CaseMetadata)

    def load_initial_alert(self, case_id: str) -> SecurityAlert:
        """Load the case alert using the T02 :class:`~app.schemas.SecurityAlert`."""
        return self._load_case_artifact(case_id, INITIAL_ALERT_FILE, SecurityAlert)

    def load_endpoint_events(self, case_id: str) -> list[EndpointEvent]:
        """Load the endpoint telemetry of one case."""
        return self._load_telemetry(case_id, ENDPOINT_EVENTS_FILE, EndpointEvent)

    def load_network_events(self, case_id: str) -> list[NetworkEvent]:
        """Load the network telemetry of one case."""
        return self._load_telemetry(case_id, NETWORK_EVENTS_FILE, NetworkEvent)

    def load_dns_events(self, case_id: str) -> list[DNSEvent]:
        """Load the DNS telemetry of one case."""
        return self._load_telemetry(case_id, DNS_EVENTS_FILE, DNSEvent)

    def load_file_records(self, case_id: str) -> list[FileRecord]:
        """Load the file telemetry of one case."""
        return self._load_telemetry(case_id, FILES_FILE, FileRecord)

    # Shared knowledge --------------------------------------------------------

    def load_ioc_reputation_records(self) -> list[IOCReputationRecord]:
        """Load the shared IOC reputation knowledge."""
        return self._load_knowledge_list(IOC_REPUTATION_FILE, IOCReputationRecord)

    def load_cti_records(self) -> list[CTIRecord]:
        """Load the shared (synthetic) CTI records."""
        return self._load_knowledge_list(CTI_RECORDS_FILE, CTIRecord)

    def load_attack_techniques(self) -> list[AttackTechniqueRecord]:
        """Load the ATT&CK technique subset used by this benchmark."""
        return self._load_knowledge_list(ATTACK_TECHNIQUES_FILE, AttackTechniqueRecord)

    # Internals ---------------------------------------------------------------

    def _case_directory(self, case_id: str) -> Path:
        case_directory = self._root / CASES_DIRECTORY / _require_case_id(case_id)
        if not case_directory.is_dir():
            cases_directory = self._root / CASES_DIRECTORY
            raise CaseNotFoundError(f"case {case_id} not found in {cases_directory}")
        return case_directory

    def _load_case_artifact(self, case_id: str, file_name: str, schema: type[ModelT]) -> ModelT:
        path = self._case_directory(case_id) / file_name
        return _parse(_read_json(path), schema, path)

    def _load_telemetry(
        self, case_id: str, file_name: str, schema: type[ModelT]
    ) -> list[ModelT]:
        path = self._case_directory(case_id) / TELEMETRY_DIRECTORY / file_name
        return _parse_list(_read_json(path), schema, path)

    def _load_knowledge_list(self, file_name: str, schema: type[ModelT]) -> list[ModelT]:
        path = self._root / KNOWLEDGE_DIRECTORY / file_name
        return _parse_list(_read_json(path), schema, path)


class GroundTruthLoader:
    """Evaluation-only access to ``datasets/ground_truth``.

    Ground truth must never reach agent/runtime code; keeping it behind its own
    loader makes that boundary explicit and testable.
    """

    def __init__(self, dataset_root: Path | str | None = None) -> None:
        self._root = _resolve_dataset_root(dataset_root)

    @property
    def dataset_root(self) -> Path:
        """Root directory of the dataset (holds cases, knowledge, ground truth)."""
        return self._root

    def list_ground_truth_cases(self) -> list[str]:
        """Return the case ids that have ground truth, sorted."""
        directory = self._root / GROUND_TRUTH_DIRECTORY
        if not directory.is_dir():
            raise DatasetFormatError(f"ground truth directory not found: {directory}")
        return sorted(entry.stem for entry in directory.glob("*.json"))

    def load_ground_truth(self, case_id: str) -> CaseGroundTruth:
        """Load the ground truth of one case."""
        path = self._root / GROUND_TRUTH_DIRECTORY / f"{_require_case_id(case_id)}.json"
        if not path.is_file():
            raise MissingGroundTruthError(f"ground truth for {case_id} not found at {path}")
        return _parse(_read_json(path), CaseGroundTruth, path)


@dataclass(frozen=True)
class DatasetValidationReport:
    """Outcome of :func:`validate_dataset`."""

    case_ids: tuple[str, ...]
    issues: tuple[str, ...]

    @property
    def ok(self) -> bool:
        """True when the dataset passed every cross-file check."""
        return not self.issues


def _load_or_record(load: Callable[[], Any], issues: list[str]) -> Any:
    """Run a loader call, recording dataset problems instead of raising."""
    try:
        return load()
    except BenchmarkError as exc:
        issues.append(str(exc))
        return None


def _string_values(payload: Any) -> set[str]:
    """Collect every string value contained in a JSON-like payload."""
    if isinstance(payload, str):
        return {payload}
    if isinstance(payload, dict):
        return {value for item in payload.values() for value in _string_values(item)}
    if isinstance(payload, list):
        return {value for item in payload for value in _string_values(item)}
    return set()


def validate_dataset(dataset_root: Path | str | None = None) -> DatasetValidationReport:
    """Validate the whole benchmark dataset and report every problem found.

    Per-record guarantees come from the Pydantic schemas - timezone-aware UTC
    timestamps, well-formed SHA256 digests, IP and port ranges, ID prefixes - so
    a violation surfaces here as a dataset issue. This function adds the
    cross-file guarantees: which cases exist, whether metadata and alerts agree,
    whether telemetry IDs are unique within a case, whether ground truth
    references existing telemetry, whether expected IOCs and techniques are
    supported by the case telemetry or shared knowledge, and whether the verdict
    distribution matches the benchmark definition.
    """
    root = _resolve_dataset_root(dataset_root)
    loader = BenchmarkLoader(root)
    truth_loader = GroundTruthLoader(root)
    issues: list[str] = []

    try:
        case_ids = loader.list_cases()
    except BenchmarkError as exc:
        return DatasetValidationReport(case_ids=(), issues=(str(exc),))

    missing_cases = sorted(set(EXPECTED_CASE_IDS) - set(case_ids))
    unexpected_cases = sorted(set(case_ids) - set(EXPECTED_CASE_IDS))
    if missing_cases:
        issues.append(f"missing cases: {', '.join(missing_cases)}")
    if unexpected_cases:
        issues.append(f"unexpected cases: {', '.join(unexpected_cases)}")

    ioc_records = _load_or_record(loader.load_ioc_reputation_records, issues)
    cti_records = _load_or_record(loader.load_cti_records, issues)
    technique_records = _load_or_record(loader.load_attack_techniques, issues)

    known_iocs: set[str] = {record.indicator for record in ioc_records or []}
    known_techniques: set[str] = {record.technique_id for record in technique_records or []}
    for cti_record in cti_records or []:
        known_iocs.update(cti_record.indicators)

    verdict_counts: Counter[str] = Counter()

    for case_id in case_ids:
        metadata = _load_or_record(lambda: loader.load_case_metadata(case_id), issues)
        alert = _load_or_record(lambda: loader.load_initial_alert(case_id), issues)
        telemetry_by_source = {
            "endpoint": _load_or_record(lambda: loader.load_endpoint_events(case_id), issues),
            "network": _load_or_record(lambda: loader.load_network_events(case_id), issues),
            "dns": _load_or_record(lambda: loader.load_dns_events(case_id), issues),
            "files": _load_or_record(lambda: loader.load_file_records(case_id), issues),
        }

        if metadata is not None and alert is not None:
            if metadata.initial_alert_id != alert.alert_id:
                issues.append(
                    f"{case_id}: metadata initial_alert_id {metadata.initial_alert_id} does not "
                    f"match the alert id {alert.alert_id}"
                )

        telemetry_ids: list[str] = []
        records: list[Any] = []
        for source, id_attribute in (
            ("endpoint", "event_id"),
            ("network", "event_id"),
            ("dns", "event_id"),
            ("files", "file_id"),
        ):
            source_records = telemetry_by_source[source]
            if source_records is None:
                continue
            if metadata is not None:
                declared = source in metadata.available_sources
                if declared and not source_records:
                    issues.append(
                        f"{case_id}: source {source!r} is declared but has no records"
                    )
                if not declared and source_records:
                    issues.append(
                        f"{case_id}: source {source!r} has records but is not declared"
                    )
            for record in source_records:
                telemetry_ids.append(getattr(record, id_attribute))
                records.append(record)

        duplicates = sorted({value for value in telemetry_ids if telemetry_ids.count(value) > 1})
        if duplicates:
            issues.append(f"{case_id}: duplicate telemetry IDs: {', '.join(duplicates)}")

        for record in records:
            if record.timestamp.tzinfo is not timezone.utc:
                issues.append(f"{case_id}: a {type(record).__name__} timestamp is not UTC")

        ground_truth = _load_or_record(lambda: truth_loader.load_ground_truth(case_id), issues)
        if ground_truth is None:
            continue

        verdict_counts[ground_truth.expected_verdict.value] += 1

        if ground_truth.case_id != case_id:
            issues.append(f"{case_id}: ground truth declares case_id {ground_truth.case_id}")

        unknown_evidence = sorted(
            set(ground_truth.key_evidence + ground_truth.acceptable_evidence) - set(telemetry_ids)
        )
        if unknown_evidence:
            issues.append(
                f"{case_id}: ground truth references unknown telemetry IDs: "
                f"{', '.join(unknown_evidence)}"
            )

        case_values: set[str] = set()
        for record in records:
            case_values.update(_string_values(json.loads(record.model_dump_json())))

        for expected_ioc in ground_truth.expected_iocs:
            if expected_ioc.indicator not in case_values and expected_ioc.indicator not in known_iocs:
                issues.append(
                    f"{case_id}: expected IOC {expected_ioc.indicator!r} has no telemetry or "
                    "knowledge support"
                )

        for expected_technique in ground_truth.expected_techniques:
            if expected_technique.technique_id not in known_techniques:
                issues.append(
                    f"{case_id}: expected technique {expected_technique.technique_id} is not in "
                    "attack_techniques knowledge"
                )

    truth_cases = _load_or_record(truth_loader.list_ground_truth_cases, issues)
    if truth_cases is not None and sorted(truth_cases) != sorted(case_ids):
        issues.append(
            "ground truth case list does not match the dataset case list: "
            f"{sorted(truth_cases)} vs {sorted(case_ids)}"
        )

    if dict(verdict_counts) != EXPECTED_VERDICT_DISTRIBUTION:
        issues.append(
            f"verdict distribution {dict(verdict_counts)} does not match the expected "
            f"{EXPECTED_VERDICT_DISTRIBUTION}"
        )

    return DatasetValidationReport(case_ids=tuple(case_ids), issues=tuple(issues))
