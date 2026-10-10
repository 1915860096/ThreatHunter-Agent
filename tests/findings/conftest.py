"""Fixtures for the T08 finding tests.

Evidence is always produced by the real T06 extractor over scripted T04
payloads, so the tests exercise the actual pipeline instead of hand-made
objects.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

import pytest

from app.evidence import DeterministicEvidenceExtractor
from app.evidence.contracts import EvidenceExtractionResult

CASE_ID = "CASE-001"
MALICIOUS_IP = "203.0.113.47"
MALICIOUS_HASH = "41ed873f46200bd7de73ed506218a92672ab61e2c63a3f159193ef2d5a5ffc00"
BENIGN_HASH = "6d975ca782ba6c6583682d59ccf081c4afcc62314d48ab74f3fc27b186185494"
UNRELATED_HASH = "a" * 64


def endpoint_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event_id": "EPE-999-001",
        "timestamp": "2026-03-02T09:11:52Z",
        "host": "ws-test-01",
        "user": "u.test",
        "event_type": "process_creation",
        "process_name": "powershell.exe",
        "pid": 4242,
        "parent_process_name": "winword.exe",
        "command_line": "powershell.exe -NoP -W Hidden -EncodedCommand AAAA",
        "file_path": None,
        "sha256": None,
        "metadata": {},
    }
    record.update(overrides)
    return record


def file_event_record(**overrides: Any) -> dict[str, Any]:
    record = endpoint_record(
        event_id="EPE-999-002",
        event_type="file_creation",
        command_line=None,
        file_path="C:\\Users\\u.test\\AppData\\Local\\Temp\\update.ps1",
    )
    record.update(overrides)
    return record


def network_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event_id": "NET-999-001",
        "timestamp": "2026-03-02T09:12:05Z",
        "src_host": "ws-test-01",
        "src_ip": "10.40.12.14",
        "src_port": 53021,
        "dst_ip": MALICIOUS_IP,
        "dst_port": 443,
        "protocol": "tcp",
        "direction": "outbound",
        "bytes_sent": 100,
        "bytes_received": 200,
        "process_name": "powershell.exe",
        "metadata": {},
    }
    record.update(overrides)
    return record


def dns_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "event_id": "DNS-999-001",
        "timestamp": "2026-03-02T09:11:53Z",
        "host": "ws-test-01",
        "src_ip": "10.40.12.14",
        "query": "sync-update.example.net",
        "record_type": "A",
        "response": MALICIOUS_IP,
        "process_name": "powershell.exe",
        "metadata": {},
    }
    record.update(overrides)
    return record


def file_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "file_id": "FILE-999-001",
        "timestamp": "2026-03-02T09:11:54Z",
        "host": "ws-test-01",
        "path": "C:\\Users\\u.test\\AppData\\Local\\Temp\\update.ps1",
        "file_name": "update.ps1",
        "sha256": MALICIOUS_HASH,
        "size": 4302,
        "signed": False,
        "signer": None,
        "source_url": "https://sync-update.example.net/update.ps1",
        "metadata": {},
    }
    record.update(overrides)
    return record


def reputation_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "indicator": MALICIOUS_IP,
        "indicator_type": "ipv4",
        "reputation": "malicious",
        "confidence": 0.9,
        "source": "benchmark-ti",
        "tags": [],
        "last_seen": "2026-03-02T09:12:06Z",
    }
    record.update(overrides)
    return record


def cti_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "cti_id": "CTI-999",
        "title": "Synthetic loader report",
        "summary": "Synthetic report summary.",
        "indicators": [MALICIOUS_IP],
        "malware_families": ["SyntheticLoader"],
        "campaigns": ["SYNTH-CAMPAIGN-TEST"],
        "technique_ids": ["T1059.001"],
        "source": "benchmark-ti",
        "published_at": "2026-02-18T00:00:00Z",
    }
    record.update(overrides)
    return record


def attack_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "description": "Adversaries may abuse PowerShell.",
        "tactics": ["execution"],
        "keywords": ["powershell"],
    }
    record.update(overrides)
    return record


def payload_for(tool_name: str, *records: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """Wrap raw records into the payload shape of one T04 tool."""
    payload: dict[str, Any] = {"case_id": CASE_ID}
    if tool_name == "search_endpoint_events":
        payload.update(items=list(records), count=len(records), truncated=False)
    elif tool_name == "search_network_activity":
        flows = [item for item in records if "NET-" in str(item.get("event_id", ""))]
        queries = [item for item in records if "DNS-" in str(item.get("event_id", ""))]
        payload.update(
            network_events=flows,
            dns_events=queries,
            network_count=len(flows),
            dns_count=len(queries),
            network_truncated=False,
            dns_truncated=False,
        )
    elif tool_name == "lookup_file_reputation":
        files = [item for item in records if "file_id" in item]
        reputations = [item for item in records if "indicator" in item]
        payload.update(files=files, reputations=reputations, count=len(files))
    elif tool_name == "lookup_ioc_reputation":
        payload.update(
            indicator=records[0].get("indicator") if records else "unknown",
            found=bool(records),
            records=list(records),
        )
    elif tool_name == "search_cti":
        cti = [item for item in records if "cti_id" in item]
        techniques = [item for item in records if "technique_id" in item]
        payload.update(
            cti_records=cti,
            attack_techniques=techniques,
            cti_count=len(cti),
            technique_count=len(techniques),
        )
    payload.update(overrides)
    return payload


@pytest.fixture
def make_extraction(
    run_factory: Any, tool_call_factory: Any, tool_result_factory: Any
) -> Callable[..., EvidenceExtractionResult]:
    """Build an EvidenceExtractionResult from (tool_name, payload) pairs."""

    def _build(
        calls: Sequence[tuple[str, dict[str, Any]]],
        *,
        case_id: str = CASE_ID,
    ) -> EvidenceExtractionResult:
        pairs = []
        for index, (tool_name, payload) in enumerate(calls, start=1):
            call = tool_call_factory(
                tool_name, {"case_id": CASE_ID}, index=index
            )
            pairs.append((call, tool_result_factory(call, payload, index=index)))
        return DeterministicEvidenceExtractor(case_id=case_id).extract(
            run_factory(pairs)
        )

    return _build


@pytest.fixture
def malicious_extraction(
    make_extraction: Callable[..., EvidenceExtractionResult]
) -> EvidenceExtractionResult:
    """Document-spawned encoded PowerShell plus a malicious IP, domain and hash."""
    return make_extraction(
        [
            (
                "search_endpoint_events",
                payload_for("search_endpoint_events", endpoint_record(), file_event_record()),
            ),
            (
                "search_network_activity",
                payload_for("search_network_activity", network_record(), dns_record()),
            ),
            (
                "lookup_file_reputation",
                payload_for(
                    "lookup_file_reputation",
                    file_record(),
                    reputation_record(indicator=MALICIOUS_HASH, indicator_type="sha256"),
                ),
            ),
            ("lookup_ioc_reputation", payload_for("lookup_ioc_reputation", reputation_record())),
        ]
    )
