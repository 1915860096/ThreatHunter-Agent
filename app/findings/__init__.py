"""Evidence-grounded security findings (T08).

This package turns a T06 :class:`~app.evidence.contracts.EvidenceExtractionResult`
into auditable :class:`~app.findings.contracts.SecurityFinding` values using
explicit, deterministic rules over **structured evidence fields** - never over
natural-language summaries and never with a second LLM call.

* every finding references existing evidence ids (``EV-``) only;
* threat-intelligence and ATT&CK records may support a finding as knowledge, but
  they are never promoted into observed attack facts;
* repeated hits of the same raw record count once, and unrelated records (other
  host, other process, other hash) are never merged into the same finding.
"""

from app.findings.contracts import (
    FINDING_ID_PREFIX,
    FindingSeverity,
    FindingSupportLevel,
    FindingType,
    SecurityFinding,
)
from app.findings.engine import FindingEngine
from app.findings.index import EvidenceIndex, normalize_indicator

__all__ = [
    "FINDING_ID_PREFIX",
    "EvidenceIndex",
    "FindingEngine",
    "FindingSeverity",
    "FindingSupportLevel",
    "FindingType",
    "SecurityFinding",
    "normalize_indicator",
]
