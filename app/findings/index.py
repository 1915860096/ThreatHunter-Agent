"""Lightweight evidence index for structured correlation (T08).

The index maps structured keys (record ids, observed indicators, file paths and
hashes, hosts, processes) to evidence ids. It is deliberately a plain in-memory
lookup - no graph database and no text-similarity heuristics: two evidence items
are only related when a structured field says so.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any, Final

from app.evidence.contracts import EvidenceExtractionResult
from app.evidence.extractor import TAG_SOURCE_CLASS_TELEMETRY
from app.schemas.evidence import Evidence, EvidenceType

TELEMETRY_RECORD_CLASSES: Final[frozenset[str]] = frozenset(
    {"endpoint_event", "network_event", "dns_event", "file_record"}
)

#: Networks considered "internal" for this benchmark. Built explicitly instead of
#: using ``ipaddress.is_private``: since Python 3.13 that flag is also true for
#: special-purpose ranges such as the RFC 5737 documentation networks, which are
#: exactly the *external* destinations this benchmark uses.
INTERNAL_NETWORKS: Final[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def normalize_indicator(value: str) -> str:
    """Normalize one indicator: IPs canonically, everything else case-folded."""
    text = value.strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text.casefold()


def is_internal_address(value: str) -> bool:
    """True for RFC1918 / loopback / link-local addresses.

    Documentation ranges (RFC 5737) count as *external*, because they are the
    synthetic external destinations of this benchmark.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in INTERNAL_NETWORKS)


class EvidenceIndex:
    """Structured lookup over one extraction result."""

    def __init__(self, extraction: EvidenceExtractionResult) -> None:
        self._extraction = extraction
        self._by_id: dict[str, Evidence] = {
            item.evidence_id: item for item in extraction.evidence
        }
        self._by_record: dict[str, list[str]] = defaultdict(list)
        self._by_indicator: dict[str, list[str]] = defaultdict(list)
        self._by_hash: dict[str, list[str]] = defaultdict(list)
        self._by_path: dict[str, list[str]] = defaultdict(list)
        self._by_host: dict[str, list[str]] = defaultdict(list)
        self._by_process: dict[str, list[str]] = defaultdict(list)
        self._by_domain: dict[str, list[str]] = defaultdict(list)
        for item in extraction.evidence:
            self._index(item)

    # Basics ----------------------------------------------------------------

    @property
    def extraction(self) -> EvidenceExtractionResult:
        """The indexed extraction result."""
        return self._extraction

    @property
    def evidence(self) -> list[Evidence]:
        """All evidence items, in extraction order."""
        return list(self._extraction.evidence)

    def get(self, evidence_id: str) -> Evidence:
        """Return one evidence item (raises ``KeyError`` when unknown)."""
        return self._by_id[evidence_id]

    def of_type(self, evidence_type: EvidenceType | str) -> list[Evidence]:
        """Evidence items of one type, in extraction order.

        Accepts the enum or its string value, so a caller cannot silently get an
        empty result by passing ``"dns_query"`` instead of the enum member.
        """
        target = EvidenceType(evidence_type)
        return [item for item in self.evidence if item.evidence_type is target]

    def telemetry(
        self, evidence_type: EvidenceType | str | None = None
    ) -> list[Evidence]:
        """Observed telemetry evidence (never knowledge records)."""
        items = [
            item
            for item in self.evidence
            if TAG_SOURCE_CLASS_TELEMETRY in item.tags
            and self.record_class(item) in TELEMETRY_RECORD_CLASSES
        ]
        if evidence_type is None:
            return items
        target = EvidenceType(evidence_type)
        return [item for item in items if item.evidence_type is target]

    def knowledge(self) -> list[Evidence]:
        """Knowledge evidence (reputation, CTI, ATT&CK)."""
        return [
            item for item in self.evidence if TAG_SOURCE_CLASS_TELEMETRY not in item.tags
        ]

    @staticmethod
    def record_class(item: Evidence) -> str:
        """The T06 record class of one evidence item."""
        value = item.content.get("record_class")
        return value if isinstance(value, str) else ""

    @staticmethod
    def record_id(item: Evidence) -> str:
        """The raw record id of one evidence item."""
        value = item.content.get("record_id")
        return value if isinstance(value, str) else ""

    def record_ids(self, items: list[Evidence]) -> list[str]:
        """Distinct raw record ids of ``items`` (repeated hits count once)."""
        ordered: list[str] = []
        for item in items:
            record_id = self.record_id(item)
            if record_id and record_id not in ordered:
                ordered.append(record_id)
        return ordered

    # Structured lookups ----------------------------------------------------

    def _items(self, mapping: dict[str, list[str]], key: str) -> list[Evidence]:
        return [self._by_id[evidence_id] for evidence_id in mapping.get(key, [])]

    def by_record(self, record_id: str) -> list[Evidence]:
        return self._items(self._by_record, record_id)

    def by_indicator(self, indicator: str) -> list[Evidence]:
        return self._items(self._by_indicator, normalize_indicator(indicator))

    def by_hash(self, sha256: str) -> list[Evidence]:
        return self._items(self._by_hash, sha256.strip().casefold())

    def by_path(self, path: str) -> list[Evidence]:
        return self._items(self._by_path, path.strip().casefold())

    def by_host(self, host: str) -> list[Evidence]:
        return self._items(self._by_host, host.strip().casefold())

    def by_process(self, process_name: str) -> list[Evidence]:
        return self._items(self._by_process, process_name.strip().casefold())

    def by_domain(self, domain: str) -> list[Evidence]:
        return self._items(self._by_domain, domain.strip().casefold())

    def observed_occurrences(self, indicator: str) -> list[Evidence]:
        """Telemetry evidence that *observes* ``indicator`` in a structured field.

        Only observed telemetry counts: a knowledge record that merely mentions
        the indicator is not an observation.
        """
        target = normalize_indicator(indicator)
        if not target:
            return []
        matches: list[Evidence] = []
        for item in self.telemetry():
            values = (
                item.content.get("src_ip"),
                item.content.get("dst_ip"),
                item.content.get("response"),
                item.content.get("query"),
                item.content.get("sha256"),
            )
            if any(
                isinstance(value, str)
                and value
                and normalize_indicator(value) == target
                for value in values
            ):
                matches.append(item)
        return matches

    def content_of(self, item: Evidence, key: str) -> Any:
        """Typed accessor for one content field."""
        return item.content.get(key)

    def _index(self, item: Evidence) -> None:
        record_id = self.record_id(item)
        if record_id:
            self._by_record[record_id].append(item.evidence_id)
        for key, mapping in (
            ("host", self._by_host),
            ("process_name", self._by_process),
            ("query", self._by_domain),
            ("path", self._by_path),
            ("file_path", self._by_path),
        ):
            value = item.content.get(key)
            if isinstance(value, str) and value:
                mapping[value.strip().casefold()].append(item.evidence_id)
        sha256 = item.content.get("sha256")
        if isinstance(sha256, str) and sha256:
            self._by_hash[sha256.strip().casefold()].append(item.evidence_id)
        indicator = item.content.get("indicator")
        if isinstance(indicator, str) and indicator:
            self._by_indicator[normalize_indicator(indicator)].append(item.evidence_id)
