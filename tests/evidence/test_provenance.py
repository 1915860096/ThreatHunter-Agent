"""Tests for raw-record locators and provenance mapping."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.evidence import (
    attack_technique_identity,
    case_telemetry_raw_ref,
    cti_record_identity,
    ioc_reputation_identity,
    knowledge_raw_ref,
    primary_provenance,
    reference_sort_key,
    sort_references,
    telemetry_identity,
)
from app.evidence.contracts import EvidenceSourceReference
from app.evidence.provenance import (
    attack_technique_raw_ref,
    cti_raw_ref,
    dns_raw_ref,
    endpoint_raw_ref,
    file_raw_ref,
    ioc_reputation_raw_ref,
    network_raw_ref,
)
from app.schemas.evidence import EvidenceSourceType


def test_raw_ref_follows_the_t03_convention() -> None:
    assert (
        case_telemetry_raw_ref("CASE-001", "endpoint_events.json", "EPE-001-003")
        == "CASE-001/telemetry/endpoint_events.json#EPE-001-003"
    )
    assert (
        knowledge_raw_ref("cti_records.json", "CTI-001") == "knowledge/cti_records.json#CTI-001"
    )


@pytest.mark.parametrize(
    ("builder", "expected"),
    [
        (lambda: endpoint_raw_ref("CASE-001", "EPE-001-003"), "CASE-001/telemetry/endpoint_events.json#EPE-001-003"),
        (lambda: network_raw_ref("CASE-001", "NET-001-003"), "CASE-001/telemetry/network_events.json#NET-001-003"),
        (lambda: dns_raw_ref("CASE-001", "DNS-001-001"), "CASE-001/telemetry/dns_events.json#DNS-001-001"),
        (lambda: file_raw_ref("CASE-001", "FILE-001-001"), "CASE-001/telemetry/files.json#FILE-001-001"),
        (lambda: ioc_reputation_raw_ref("203.0.113.47", "benchmark-ti"), "knowledge/ioc_reputation.json#203.0.113.47|benchmark-ti"),
        (lambda: cti_raw_ref("CTI-001"), "knowledge/cti_records.json#CTI-001"),
        (lambda: attack_technique_raw_ref("T1059.001"), "knowledge/attack_techniques.json#T1059.001"),
    ],
)
def test_each_record_kind_has_a_stable_locator(builder: object, expected: str) -> None:
    assert builder() == expected  # type: ignore[operator]


def reference(tool_call_id: str, tool_result_id: str, record_id: str) -> EvidenceSourceReference:
    return EvidenceSourceReference(
        source_type=EvidenceSourceType.TOOL,
        source_name="search_cti",
        tool_call_id=tool_call_id,
        tool_result_id=tool_result_id,
        record_id=record_id,
        raw_ref=cti_raw_ref(record_id),
    )


def test_references_sort_deterministically() -> None:
    references = [
        reference("TC-000002", "TR-0002", "CTI-002"),
        reference("TC-000001", "TR-0001", "CTI-001"),
    ]

    ordered = sort_references(references)

    assert [item.tool_result_id for item in ordered] == ["TR-0001", "TR-0002"]
    assert ordered == sort_references(list(reversed(references)))
    assert reference_sort_key(ordered[0]) < reference_sort_key(ordered[1])


def test_primary_provenance_uses_the_first_stable_reference() -> None:
    provenance = primary_provenance(
        [
            reference("TC-000002", "TR-0002", "CTI-002"),
            reference("TC-000001", "TR-0001", "CTI-001"),
        ]
    )

    assert provenance.source_type is EvidenceSourceType.TOOL
    assert provenance.tool_call_id == "TC-000001"
    assert provenance.tool_result_id == "TR-0001"
    assert provenance.raw_ref == "knowledge/cti_records.json#CTI-001"


def test_primary_provenance_satisfies_the_frozen_t02_contract() -> None:
    provenance = primary_provenance([reference("TC-000001", "TR-0001", "CTI-001")])

    assert provenance.source_name == "search_cti"
    with pytest.raises(ValidationError):
        # T02 requires both tool ids whenever the source type is "tool".
        type(provenance)(
            source_type=EvidenceSourceType.TOOL,
            source_name="search_cti",
        )


def test_record_identities_are_stable_and_namespaced() -> None:
    assert telemetry_identity("endpoint_event", "EPE-001-003") == "endpoint_event:EPE-001-003"
    assert cti_record_identity.__name__ == "cti_record_identity"
    assert attack_technique_identity.__name__ == "attack_technique_identity"
    assert ioc_reputation_identity.__name__ == "ioc_reputation_identity"
