"""Tests for the tool input and payload contracts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.benchmark.loader import BenchmarkLoader
from app.schemas.findings import IOCReputation, IOCType
from app.tools import (
    CTISearchInput,
    CTISearchPayload,
    EndpointSearchInput,
    EndpointSearchPayload,
    FileReputationInput,
    FileReputationPayload,
    IOCReputationInput,
    IOCReputationPayload,
    NetworkSearchInput,
    NetworkSearchPayload,
)

CASE_ID = "CASE-001"


def test_endpoint_search_input_defaults() -> None:
    request = EndpointSearchInput(case_id=CASE_ID)

    assert request.limit == 100
    assert request.event_types is None
    assert request.start_time is None


def test_network_search_input_defaults() -> None:
    request = NetworkSearchInput(case_id=CASE_ID)

    assert request.limit == 100
    assert request.include_network is True
    assert request.include_dns is True


def test_file_reputation_input_accepts_each_core_field() -> None:
    assert FileReputationInput(case_id=CASE_ID, file_name="update.ps1").file_name == "update.ps1"
    assert FileReputationInput(case_id=CASE_ID, path="C:\\Temp\\update.ps1").path
    assert FileReputationInput(case_id=CASE_ID, sha256="a" * 64).sha256


def test_ioc_reputation_input_requires_indicator() -> None:
    assert IOCReputationInput(indicator="10.30.8.15").ioc_type is None

    with pytest.raises(ValidationError):
        IOCReputationInput(indicator="   ")


def test_cti_search_input_defaults() -> None:
    request = CTISearchInput(query="certutil")

    assert request.limit == 20
    assert request.indicator is None
    assert request.technique_id is None


@pytest.mark.parametrize("limit", [1, 500])
def test_telemetry_limit_boundaries_are_inclusive(limit: int) -> None:
    assert EndpointSearchInput(case_id=CASE_ID, limit=limit).limit == limit
    assert NetworkSearchInput(case_id=CASE_ID, limit=limit).limit == limit


@pytest.mark.parametrize("limit", [0, -1, 501])
def test_invalid_telemetry_limits_are_rejected(limit: int) -> None:
    with pytest.raises(ValidationError) as exc_info:
        EndpointSearchInput(case_id=CASE_ID, limit=limit)

    assert exc_info.value.errors()[0]["loc"] == ("limit",)

    with pytest.raises(ValidationError):
        NetworkSearchInput(case_id=CASE_ID, limit=limit)


@pytest.mark.parametrize("limit", [1, 100])
def test_cti_limit_boundaries_are_inclusive(limit: int) -> None:
    assert CTISearchInput(query="powershell", limit=limit).limit == limit


@pytest.mark.parametrize("limit", [0, 101])
def test_invalid_cti_limits_are_rejected(limit: int) -> None:
    with pytest.raises(ValidationError) as exc_info:
        CTISearchInput(query="powershell", limit=limit)

    assert exc_info.value.errors()[0]["loc"] == ("limit",)


@pytest.mark.parametrize(
    "model_kwargs",
    [
        {"case_id": CASE_ID, "start_time": "2026-03-02T09:11:52"},
        {"case_id": CASE_ID, "end_time": "2026-03-02T09:11:52"},
    ],
)
def test_naive_datetimes_are_rejected_by_search_inputs(
    model_kwargs: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        EndpointSearchInput(**model_kwargs)

    with pytest.raises(ValidationError):
        NetworkSearchInput(**model_kwargs)


def test_timezone_aware_window_is_normalised_to_utc() -> None:
    request = EndpointSearchInput(
        case_id=CASE_ID,
        start_time="2026-03-02T17:11:52+08:00",
        end_time="2026-03-02T17:11:52+08:00",
    )

    assert request.start_time is not None
    assert request.start_time.utcoffset().total_seconds() == 0
    assert request.start_time.hour == 9


def test_inverted_time_window_is_rejected() -> None:
    with pytest.raises(ValidationError) as exc_info:
        EndpointSearchInput(
            case_id=CASE_ID,
            start_time="2026-03-02T10:00:00Z",
            end_time="2026-03-02T09:00:00Z",
        )

    assert "start_time must not be later than end_time" in str(exc_info.value)

    with pytest.raises(ValidationError):
        NetworkSearchInput(
            case_id=CASE_ID,
            start_time="2026-03-02T10:00:00Z",
            end_time="2026-03-02T09:00:00Z",
        )


def test_network_search_requires_at_least_one_source() -> None:
    with pytest.raises(ValidationError, match="include_network or include_dns"):
        NetworkSearchInput(case_id=CASE_ID, include_network=False, include_dns=False)


def test_file_reputation_requires_a_core_query_field() -> None:
    with pytest.raises(ValidationError, match="sha256, path or file_name"):
        FileReputationInput(case_id=CASE_ID)

    with pytest.raises(ValidationError, match="sha256, path or file_name"):
        FileReputationInput(case_id=CASE_ID, host="ws-fin-014")


def test_cti_search_requires_a_query_field() -> None:
    with pytest.raises(ValidationError, match="at least one of query, indicator or technique_id"):
        CTISearchInput()


@pytest.mark.parametrize("blank", ["", "   "])
def test_cti_search_rejects_blank_query_and_indicator(blank: str) -> None:
    with pytest.raises(ValidationError, match="must not be empty or whitespace"):
        CTISearchInput(query=blank)

    with pytest.raises(ValidationError, match="must not be empty or whitespace"):
        CTISearchInput(indicator=blank)


@pytest.mark.parametrize("case_id", ["CASE1", "case-001", "ALT-001"])
def test_search_inputs_validate_case_id_prefix(case_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        EndpointSearchInput(case_id=case_id)

    assert exc_info.value.errors()[0]["loc"] == ("case_id",)


@pytest.mark.parametrize("technique_id", ["T1059.1", "1059", "TA0001"])
def test_cti_search_validates_technique_id(technique_id: str) -> None:
    with pytest.raises(ValidationError) as exc_info:
        CTISearchInput(technique_id=technique_id)

    assert exc_info.value.errors()[0]["loc"] == ("technique_id",)


@pytest.mark.parametrize("ip_value", ["203.0.113.999", "not-an-ip"])
def test_network_search_validates_ip_filter(ip_value: str) -> None:
    with pytest.raises(ValidationError):
        NetworkSearchInput(case_id=CASE_ID, dst_ip=ip_value)


@pytest.mark.parametrize("port", [0, 65536])
def test_network_search_validates_port_filter(port: int) -> None:
    with pytest.raises(ValidationError):
        NetworkSearchInput(case_id=CASE_ID, dst_port=port)


def test_file_reputation_validates_sha256_filter() -> None:
    with pytest.raises(ValidationError):
        FileReputationInput(case_id=CASE_ID, sha256="not-a-hash")


# Payload schemas -------------------------------------------------------------


def test_endpoint_search_payload_defaults() -> None:
    payload = EndpointSearchPayload(case_id=CASE_ID, count=0)

    assert payload.items == []
    assert payload.truncated is False


def test_network_search_payload_defaults() -> None:
    payload = NetworkSearchPayload(case_id=CASE_ID, network_count=0, dns_count=0)

    assert payload.network_events == []
    assert payload.dns_events == []
    assert payload.network_truncated is False
    assert payload.dns_truncated is False


def test_file_reputation_payload_defaults() -> None:
    payload = FileReputationPayload(case_id=CASE_ID, count=0)

    assert payload.files == []
    assert payload.reputations == []


def test_cti_search_payload_defaults() -> None:
    payload = CTISearchPayload(cti_count=0, technique_count=0)

    assert payload.cti_records == []
    assert payload.attack_techniques == []
    assert payload.cti_truncated is False
    assert payload.technique_truncated is False


def test_payload_collections_are_not_shared_between_instances() -> None:
    first = EndpointSearchPayload(case_id=CASE_ID, count=0)
    second = EndpointSearchPayload(case_id=CASE_ID, count=0)

    first.items.append(BenchmarkLoader().load_endpoint_events(CASE_ID)[0])

    assert second.items == []


def test_ioc_reputation_payload_requires_consistent_found_flag() -> None:
    with pytest.raises(ValidationError, match="must not be empty when found is True"):
        IOCReputationPayload(indicator="sync-update.example.net", found=True)

    records = BenchmarkLoader().load_ioc_reputation_records()[:1]
    with pytest.raises(ValidationError, match="must be empty when found is False"):
        IOCReputationPayload(indicator="sync-update.example.net", found=False, records=records)

    assert IOCReputationPayload(indicator="unknown.example.net", found=False).records == []


def test_ioc_reputation_payload_accepts_known_indicator() -> None:
    records = [
        record
        for record in BenchmarkLoader().load_ioc_reputation_records()
        if record.reputation is IOCReputation.UNKNOWN and record.indicator_type is IOCType.SHA256
    ]
    payload = IOCReputationPayload(
        indicator=records[0].indicator, ioc_type=IOCType.SHA256, found=True, records=records
    )

    assert payload.found is True
    assert payload.records[0].reputation is IOCReputation.UNKNOWN
