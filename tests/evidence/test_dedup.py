"""Tests for stable record identities and deduplication."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from app.benchmark.schemas import (
    AttackTechniqueRecord,
    CaseId,
    CTIRecord,
    IOCReputationRecord,
)
from app.schemas.common import EvidenceId
from app.evidence import (
    EvidenceAccumulator,
    attack_technique_identity,
    cti_record_identity,
    ioc_reputation_identity,
    telemetry_identity,
)
from app.evidence.contracts import EvidenceSourceReference
from app.evidence.dedup import ATTACK_RECORD_CLASS, CTI_RECORD_CLASS
from app.schemas.evidence import EvidenceSourceType, EvidenceType
from tests.conftest import INCIDENT_ID, START


def reputation(
    *,
    indicator: str = "203.0.113.47",
    source: str = "benchmark-ti",
    reputation_value: str = "malicious",
    confidence: float = 0.9,
    indicator_type: str = "ipv4",
) -> IOCReputationRecord:
    return IOCReputationRecord.model_validate(
        {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": reputation_value,
            "confidence": confidence,
            "source": source,
        }
    )


def reference(index: int, record_id: str, *, tool_name: str = "search_cti") -> EvidenceSourceReference:
    return EvidenceSourceReference(
        source_type=EvidenceSourceType.TOOL,
        source_name=tool_name,
        tool_call_id=f"TC-{index:06d}",
        tool_result_id=f"TR-{index:04d}",
        record_id=record_id,
        raw_ref=f"knowledge/cti_records.json#{record_id}",
    )


def add(
    accumulator: EvidenceAccumulator,
    *,
    identity: str,
    reference_item: EvidenceSourceReference,
    tags: list[str] | None = None,
) -> None:
    accumulator.add(
        identity=identity,
        evidence_type=EvidenceType.THREAT_INTELLIGENCE,
        summary=f"summary for {identity}",
        content={"record_id": identity},
        observed_at=START,
        collected_at=START,
        reliability=0.6,
        tags=tags if tags is not None else ["base"],
        reference=reference_item,
    )


def test_identity_uses_schema_ids() -> None:
    assert telemetry_identity(CTI_RECORD_CLASS, "CTI-001") == "cti_record:CTI-001"
    assert telemetry_identity(ATTACK_RECORD_CLASS, "T1059.001") == "attack_technique:T1059.001"


def test_ioc_identity_is_case_insensitive_but_keeps_sources_apart() -> None:
    first = reputation(indicator="Sync-Update.Example.NET", source="benchmark-ti")
    same = reputation(indicator="sync-update.example.net", source="BENCHMARK-TI")
    other_source = reputation(indicator="sync-update.example.net", source="community-feed")
    other_reputation = reputation(reputation_value="suspicious")

    assert ioc_reputation_identity(first) == ioc_reputation_identity(same)
    assert ioc_reputation_identity(first) != ioc_reputation_identity(other_source)
    assert ioc_reputation_identity(first) != ioc_reputation_identity(other_reputation)


def test_cti_and_attack_identities_stay_separate() -> None:
    cti = CTIRecord.model_validate(
        {
            "cti_id": "CTI-001",
            "title": "Title",
            "summary": "Summary",
            "indicators": [],
            "technique_ids": ["T1059.001"],
            "source": "benchmark-ti",
            "published_at": START,
        }
    )
    technique = AttackTechniqueRecord.model_validate(
        {
            "technique_id": "T1059.001",
            "name": "PowerShell",
            "description": "Description",
        }
    )

    assert cti_record_identity(cti) == "cti_record:CTI-001"
    assert attack_technique_identity(technique) == "attack_technique:T1059.001"
    assert cti_record_identity(cti) != attack_technique_identity(technique)


def test_accumulator_deduplicates_and_keeps_every_source() -> None:
    accumulator = EvidenceAccumulator()
    identity = telemetry_identity(CTI_RECORD_CLASS, "CTI-001")

    add(accumulator, identity=identity, reference_item=reference(2, "CTI-001"))
    add(accumulator, identity=identity, reference_item=reference(1, "CTI-001"), tags=["extra"])

    assert accumulator.candidate_count == 2
    evidence, sources = accumulator.build(incident_id=INCIDENT_ID)

    assert len(evidence) == 1
    assert evidence[0].evidence_id == "EV-000001"
    assert evidence[0].tags == ["base", "extra"]
    assert [item.tool_result_id for item in sources["EV-000001"]] == ["TR-0001", "TR-0002"]
    assert evidence[0].provenance.tool_result_id == "TR-0001"


def test_accumulator_keeps_distinct_records_apart() -> None:
    accumulator = EvidenceAccumulator()

    add(accumulator, identity=telemetry_identity(CTI_RECORD_CLASS, "CTI-001"), reference_item=reference(1, "CTI-001"))
    add(accumulator, identity=telemetry_identity(CTI_RECORD_CLASS, "CTI-002"), reference_item=reference(1, "CTI-002"))
    add(accumulator, identity=telemetry_identity(ATTACK_RECORD_CLASS, "T1059.001"), reference_item=reference(1, "T1059.001"))

    evidence, sources = accumulator.build(incident_id=INCIDENT_ID)

    assert [item.evidence_id for item in evidence] == ["EV-000001", "EV-000002", "EV-000003"]
    assert set(sources) == {"EV-000001", "EV-000002", "EV-000003"}
    assert accumulator.candidate_count == 3


def test_accumulator_is_insertion_ordered_and_repeatable() -> None:
    def build() -> list[str]:
        accumulator = EvidenceAccumulator()
        for index, record_id in enumerate(["CTI-002", "CTI-001", "CTI-002"], start=1):
            add(
                accumulator,
                identity=telemetry_identity(CTI_RECORD_CLASS, record_id),
                reference_item=reference(index, record_id),
            )
        evidence, _ = accumulator.build(incident_id=INCIDENT_ID)
        return [item.evidence_id for item in evidence]

    assert build() == ["EV-000001", "EV-000002"]
    assert build() == build()


def test_t02_id_aliases_are_reused_and_keep_the_ev_prefix() -> None:
    class Probe(BaseModel):
        evidence_id: EvidenceId
        case_id: CaseId

    probe = Probe(evidence_id="EV-000001", case_id="CASE-001")

    assert probe.evidence_id == "EV-000001"
    with pytest.raises(ValidationError):
        Probe(evidence_id="EVD-000001", case_id="CASE-001")
