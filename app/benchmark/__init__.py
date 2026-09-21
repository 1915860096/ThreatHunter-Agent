"""Security investigation benchmark: dataset schemas, loaders and validation.

This package is dataset infrastructure only. It defines the *benchmark* data
contracts (synthetic telemetry, shared knowledge, ground truth), the loaders
that read them, and cross-file dataset validation.

The benchmark does **not** implement runtime security tools, agents, retrieval
or evaluation metrics, and it keeps the T02 domain semantics untouched:

    Telemetry != ToolResult != Evidence != Finding

* Telemetry is the raw-ish synthetic security data shipped in ``datasets/cases``.
* ``ToolResult`` (future) is what a tool returns when querying telemetry.
* ``Evidence`` (future) is normalised, provenance-carrying evidence.
* ``Finding`` (future) is a conclusion supported by evidence.
* Ground truth lives in ``datasets/ground_truth``, is evaluation-only, and is
  reachable exclusively through :class:`~app.benchmark.loader.GroundTruthLoader`.
"""

from app.benchmark.loader import (
    BenchmarkError,
    BenchmarkLoader,
    CaseNotFoundError,
    DatasetFormatError,
    DatasetValidationReport,
    GroundTruthLoader,
    MissingGroundTruthError,
    validate_dataset,
)
from app.benchmark.schemas import (
    AttackTechniqueRecord,
    CaseGroundTruth,
    CaseMetadata,
    CTIRecord,
    DNSEvent,
    EndpointEvent,
    ExpectedInvestigation,
    FileRecord,
    GroundTruthIOC,
    GroundTruthTechnique,
    IOCReputationRecord,
    NetworkEvent,
)

__all__ = [
    "AttackTechniqueRecord",
    "BenchmarkError",
    "BenchmarkLoader",
    "CTIRecord",
    "CaseGroundTruth",
    "CaseMetadata",
    "CaseNotFoundError",
    "DNSEvent",
    "DatasetFormatError",
    "DatasetValidationReport",
    "EndpointEvent",
    "ExpectedInvestigation",
    "FileRecord",
    "GroundTruthIOC",
    "GroundTruthLoader",
    "GroundTruthTechnique",
    "IOCReputationRecord",
    "MissingGroundTruthError",
    "NetworkEvent",
    "validate_dataset",
]
