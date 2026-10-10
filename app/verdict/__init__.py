"""Explainable verdict engine (T08).

The verdict is a deterministic rule application over findings, the run's
terminal state and the recorded information gaps - no second LLM call, no
calibrated probability. Dispositions reuse the frozen T02
``InvestigationVerdict`` enum; confidence is expressed as ``low``/``medium``/
``high`` levels only.
"""

from app.verdict.contracts import (
    VerdictConfidence,
    VerdictDisposition,
    VerdictFindingIds,
    InvestigationVerdict,
)
from app.verdict.engine import (
    RULE_VERDICT_BENIGN,
    RULE_VERDICT_INCONCLUSIVE,
    RULE_VERDICT_MALICIOUS,
    RULE_VERDICT_SUSPICIOUS,
    VerdictEngine,
)

__all__ = [
    "RULE_VERDICT_BENIGN",
    "RULE_VERDICT_INCONCLUSIVE",
    "RULE_VERDICT_MALICIOUS",
    "RULE_VERDICT_SUSPICIOUS",
    "InvestigationVerdict",
    "VerdictConfidence",
    "VerdictDisposition",
    "VerdictEngine",
    "VerdictFindingIds",
]
