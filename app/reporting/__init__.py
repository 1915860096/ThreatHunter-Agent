"""Investigation summaries built from extracted evidence (T06).

The summary layer reports *what the deterministic tools returned* and *what is
missing*. It never produces a verdict, a risk score or a confidence, and it
never promotes knowledge references (IOC reputation, CTI, ATT&CK) into
confirmed activity.
"""

from app.reporting.contracts import (
    InvestigationSummary,
    SummaryObservation,
    SummaryObservationCategory,
)
from app.reporting.summary import DeterministicSummaryBuilder

__all__ = [
    "DeterministicSummaryBuilder",
    "InvestigationSummary",
    "SummaryObservation",
    "SummaryObservationCategory",
]
