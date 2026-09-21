"""Domain schemas: the data contracts shared by every later ThreatHunter stage.

Import from this package rather than from the individual modules so the
contract surface stays in one place::

    from app.schemas import Evidence, InvestigationReport, SecurityAlert

Layout:

* ``common``        - ID prefix helpers, timezone handling, bounded scores
* ``alert``         - inbound security alerts
* ``investigation`` - investigation plans and steps
* ``tools``         - tool calls and raw tool results
* ``evidence``      - normalised evidence and its provenance
* ``findings``      - IOC and ATT&CK findings supported by evidence
* ``report``        - timelines, recommendations and the final report
* ``health``        - service health payload
"""

from app.schemas.alert import AlertSeverity, SecurityAlert
from app.schemas.evidence import (
    Evidence,
    EvidenceProvenance,
    EvidenceSourceType,
    EvidenceType,
)
from app.schemas.findings import (
    IOCFinding,
    IOCReputation,
    IOCType,
    AttackTechniqueFinding,
)
from app.schemas.health import HealthResponse
from app.schemas.investigation import (
    InvestigationPlan,
    InvestigationStep,
    InvestigationStepStatus,
)
from app.schemas.report import (
    InvestigationReport,
    InvestigationVerdict,
    Recommendation,
    RecommendationPriority,
    TimelineEvent,
)
from app.schemas.tools import ToolCall, ToolCallStatus, ToolResult

__all__ = [
    "AlertSeverity",
    "AttackTechniqueFinding",
    "Evidence",
    "EvidenceProvenance",
    "EvidenceSourceType",
    "EvidenceType",
    "HealthResponse",
    "IOCFinding",
    "IOCReputation",
    "IOCType",
    "InvestigationPlan",
    "InvestigationReport",
    "InvestigationStep",
    "InvestigationStepStatus",
    "InvestigationVerdict",
    "Recommendation",
    "RecommendationPriority",
    "SecurityAlert",
    "TimelineEvent",
    "ToolCall",
    "ToolCallStatus",
    "ToolResult",
]
