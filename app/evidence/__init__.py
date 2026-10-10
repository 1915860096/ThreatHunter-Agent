"""Deterministic evidence extraction for investigation runs (T06).

This package turns a T05 :class:`~app.runtime.contracts.InvestigationRun` into
normalised, provenance-carrying :class:`~app.schemas.evidence.Evidence`:

* only *facts* found in **successful** tool results become evidence - a failed
  tool call yields no evidence, and a successful query with zero matches yields
  no evidence either (an empty result is a gap, never "benign");
* knowledge hits (IOC reputation, CTI, ATT&CK) stay clearly marked as
  references, never as confirmed activity;
* every evidence item carries T02 provenance (tool call, tool result, raw
  record locator) plus a T06 multi-source index, because the frozen T02
  ``EvidenceProvenance`` can describe only one source;
* extraction is deterministic: same run in, same evidence ids, order and source
  maps out.

No LLM, no retrieval, no verdict: T06 extracts evidence and summarises what the
tools returned.
"""

from app.evidence.contracts import EvidenceExtractionResult, EvidenceSourceReference
from app.evidence.dedup import (
    EvidenceAccumulator,
    attack_technique_identity,
    cti_record_identity,
    ioc_reputation_identity,
    telemetry_identity,
)
from app.evidence.extractor import DeterministicEvidenceExtractor
from app.evidence.provenance import (
    case_telemetry_raw_ref,
    knowledge_raw_ref,
    primary_provenance,
    reference_sort_key,
    sort_references,
)

__all__ = [
    "DeterministicEvidenceExtractor",
    "EvidenceAccumulator",
    "EvidenceExtractionResult",
    "EvidenceSourceReference",
    "attack_technique_identity",
    "case_telemetry_raw_ref",
    "cti_record_identity",
    "ioc_reputation_identity",
    "knowledge_raw_ref",
    "primary_provenance",
    "reference_sort_key",
    "sort_references",
    "telemetry_identity",
]
