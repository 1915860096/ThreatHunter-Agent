"""Deterministic verdict rules (T08).

```
findings + run status/stop_reason + information gaps -> disposition + confidence
```

Explicit rules (first match wins), each recorded in ``rule_id``:

* ``RULE-VERDICT-MAL-001``  malicious   - a malicious indicator match *and* a linked
  behaviour finding (cross-source bar); a knowledge-only hit is never enough.
* ``RULE-VERDICT-SUS-001``  suspicious  - malicious indicator without a linked
  behaviour, or any finding of medium severity or higher.
* ``RULE-VERDICT-BEN-001``  benign      - an observed allow-list (benign reputation)
  match, no finding of medium severity or higher, and a completed investigation.
* ``RULE-VERDICT-INC-001``  inconclusive - everything else, including empty or
  unlinked evidence.

Unknown reputation, zero results and missing tool output never produce benign.
An investigation that stopped early keeps an explicit partial-coverage
limitation, and its confidence is capped at medium.
"""

from __future__ import annotations

from typing import Final

from app.evidence.contracts import EvidenceExtractionResult
from app.findings.contracts import FindingSeverity, FindingType, SecurityFinding
from app.findings.index import EvidenceIndex, normalize_indicator
from app.reporting.contracts import InvestigationSummary
from app.runtime.contracts import InvestigationRun, RuntimeStatus, StopReason
from app.schemas.evidence import Evidence, EvidenceType
from app.verdict.contracts import (
    InvestigationVerdict,
    VerdictConfidence,
    VerdictDisposition,
)

RULE_VERDICT_MALICIOUS: Final[str] = "RULE-VERDICT-MAL-001"
RULE_VERDICT_SUSPICIOUS: Final[str] = "RULE-VERDICT-SUS-001"
RULE_VERDICT_BENIGN: Final[str] = "RULE-VERDICT-BEN-001"
RULE_VERDICT_INCONCLUSIVE: Final[str] = "RULE-VERDICT-INC-001"

SCRIPT_INTERPRETERS: Final[frozenset[str]] = frozenset(
    {"powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"}
)

PARTIAL_INVESTIGATION_LIMITATION: Final[str] = (
    "The investigation did not complete, so the evidence set is partial and the verdict is "
    "capped at medium confidence."
)
UNCALIBRATED_NOTE: Final[str] = (
    "This verdict is an evidence-grounded assessment, not a calibrated probability."
)

#: Severity rank of "medium" in :class:`~app.findings.contracts.FindingSeverity`
#: (low=0, medium=1, high=2, critical=3).
MEDIUM_SEVERITY_RANK: Final[int] = 1


class VerdictEngine:
    """Applies the T08 verdict rules."""

    def build(
        self,
        *,
        run: InvestigationRun,
        extraction: EvidenceExtractionResult,
        summary: InvestigationSummary,
        findings: list[SecurityFinding],
    ) -> InvestigationVerdict:
        """Return the deterministic verdict of one investigation."""
        index = EvidenceIndex(extraction)
        completed = (
            run.status is RuntimeStatus.COMPLETED
            and run.stop_reason is StopReason.COMPLETED
        )
        limitations: list[str] = [UNCALIBRATED_NOTE]
        if not completed:
            limitations.append(PARTIAL_INVESTIGATION_LIMITATION)

        benign_evidence = self._observed_benign_evidence(index)
        counter_evidence_ids = [item.evidence_id for item in benign_evidence]
        malicious_findings = [item for item in findings if item.is_malicious_grade]
        behaviour_findings = [
            item
            for item in findings
            if item.finding_type
            in (
                FindingType.SUSPICIOUS_PROCESS_EXECUTION,
                FindingType.SUSPICIOUS_FILE_ARTIFACT,
                FindingType.SUSPICIOUS_NETWORK_ACTIVITY,
                FindingType.CORRELATED_ATTACK_PATTERN,
            )
        ]
        pairs = self._cross_source_pairs(index, malicious_findings, behaviour_findings)

        if pairs and (completed or len(pairs) >= 2):
            supporting = self._ordered_ids(
                [finding for pair in pairs for finding in pair]
            )
            return self._verdict(
                run=run,
                summary=summary,
                disposition=VerdictDisposition.MALICIOUS,
                confidence=(
                    VerdictConfidence.HIGH if completed else VerdictConfidence.MEDIUM
                ),
                rationale=self._malicious_rationale(index, pairs),
                supporting=supporting,
                counter_evidence_ids=counter_evidence_ids,
                limitations=limitations,
                rule_id=RULE_VERDICT_MALICIOUS,
            )

        if malicious_findings:
            return self._verdict(
                run=run,
                summary=summary,
                disposition=VerdictDisposition.SUSPICIOUS,
                confidence=VerdictConfidence.MEDIUM,
                rationale=(
                    f"{len(malicious_findings)} malicious indicator match(es) were observed, but "
                    "no independent behaviour finding is structurally linked to them, so the "
                    "cross-source bar for a malicious disposition is not met."
                ),
                supporting=[item.finding_id for item in malicious_findings],
                counter_evidence_ids=counter_evidence_ids,
                limitations=limitations,
                rule_id=RULE_VERDICT_SUSPICIOUS,
            )

        escalated = [
            item for item in findings if item.severity_rank >= MEDIUM_SEVERITY_RANK
        ]
        if escalated:
            return self._verdict(
                run=run,
                summary=summary,
                disposition=VerdictDisposition.SUSPICIOUS,
                confidence=(
                    VerdictConfidence.HIGH
                    if any(item.finding_type is FindingType.CORRELATED_ATTACK_PATTERN for item in escalated)
                    else VerdictConfidence.MEDIUM
                ),
                rationale=(
                    f"{len(escalated)} finding(s) of medium severity or higher describe suspicious "
                    "behaviour, but no malicious indicator with a linked behaviour was observed."
                ),
                supporting=[item.finding_id for item in escalated],
                counter_evidence_ids=counter_evidence_ids,
                limitations=limitations,
                rule_id=RULE_VERDICT_SUSPICIOUS,
            )

        if benign_evidence and completed:
            return self._verdict(
                run=run,
                summary=summary,
                disposition=VerdictDisposition.BENIGN,
                confidence=(
                    VerdictConfidence.HIGH
                    if not summary.information_gaps
                    else VerdictConfidence.MEDIUM
                ),
                rationale=(
                    f"{len(benign_evidence)} observed allow-list (benign reputation) match(es) "
                    "support this activity, and no finding of medium severity or higher was "
                    "produced. This is a positive allow-list match, not an absence-of-evidence "
                    "judgement."
                ),
                supporting=[
                    item.finding_id
                    for item in findings
                    if item.severity_rank < MEDIUM_SEVERITY_RANK
                ],
                counter_evidence_ids=[],
                limitations=limitations
                + [
                    "Benign dispositions require a positive allow-list match; unknown or "
                    "unmatched indicators never produce benign."
                ],
                rule_id=RULE_VERDICT_BENIGN,
            )

        return self._verdict(
            run=run,
            summary=summary,
            disposition=VerdictDisposition.INCONCLUSIVE,
            confidence=VerdictConfidence.LOW,
            rationale=(
                "No finding reached the suspicious threshold"
                + (" and the investigation did not complete" if not completed else "")
                + (f"; {len(summary.information_gaps)} information gap(s) remain" if summary.information_gaps else "")
                + ". The available evidence cannot support a malicious, suspicious or benign "
                "assessment."
            ),
            supporting=[],
            counter_evidence_ids=counter_evidence_ids,
            limitations=limitations,
            rule_id=RULE_VERDICT_INCONCLUSIVE,
        )

    # Internals --------------------------------------------------------------

    def _verdict(
        self,
        *,
        run: InvestigationRun,
        summary: InvestigationSummary,
        disposition: VerdictDisposition,
        confidence: VerdictConfidence,
        rationale: str,
        supporting: list[str],
        counter_evidence_ids: list[str],
        limitations: list[str],
        rule_id: str,
    ) -> InvestigationVerdict:
        return InvestigationVerdict(
            incident_id=run.incident_id,
            disposition=disposition,
            confidence_level=confidence,
            rationale=rationale,
            supporting_finding_ids=supporting,
            counter_evidence_ids=counter_evidence_ids,
            information_gaps=list(summary.information_gaps),
            limitations=list(dict.fromkeys(limitations)),
            rule_id=rule_id,
        )

    @staticmethod
    def _ordered_ids(findings: list[SecurityFinding]) -> list[str]:
        ordered: list[str] = []
        for finding in findings:
            if finding.finding_id not in ordered:
                ordered.append(finding.finding_id)
        return sorted(ordered)

    @staticmethod
    def _observed_benign_evidence(index: EvidenceIndex) -> list[Evidence]:
        observed: list[Evidence] = []
        for item in index.of_type(EvidenceType.IOC_REPUTATION):
            if index.content_of(item, "reputation") != "benign":
                continue
            indicator = index.content_of(item, "indicator")
            if isinstance(indicator, str) and index.observed_occurrences(indicator):
                observed.append(item)
        return observed

    def _cross_source_pairs(
        self,
        index: EvidenceIndex,
        malicious_findings: list[SecurityFinding],
        behaviour_findings: list[SecurityFinding],
    ) -> list[tuple[SecurityFinding, SecurityFinding]]:
        """Pairs a malicious indicator match with a structurally linked behaviour finding."""
        pairs: list[tuple[SecurityFinding, SecurityFinding]] = []
        for malicious in malicious_findings:
            for indicator in malicious.related_indicators:
                target = normalize_indicator(indicator)
                if not target:
                    continue
                for behaviour in behaviour_findings:
                    if self._links(index, behaviour, target, indicator):
                        pairs.append((malicious, behaviour))
        return pairs

    @staticmethod
    def _links(
        index: EvidenceIndex, behaviour: SecurityFinding, target: str, raw: str
    ) -> bool:
        hash_like = len(raw) == 64 and all(char in "0123456789abcdefABCDEF" for char in raw)
        for evidence_id in behaviour.evidence_ids:
            item = index.get(evidence_id)
            if hash_like:
                if normalize_indicator(str(index.content_of(item, "sha256") or "")) == target:
                    return True
                continue
            if normalize_indicator(str(index.content_of(item, "dst_ip") or "")) == target:
                return True
            if normalize_indicator(str(index.content_of(item, "response") or "")) == target:
                return True
            if normalize_indicator(str(index.content_of(item, "query") or "")) == target:
                process = str(index.content_of(item, "process_name") or "").casefold()
                if process and process in SCRIPT_INTERPRETERS:
                    return True
        if hash_like:
            return False
        # A behaviour finding may describe the same process that produced the indicator.
        for evidence_id in behaviour.evidence_ids:
            item = index.get(evidence_id)
            process = str(index.content_of(item, "process_name") or "").casefold()
            if process and process in SCRIPT_INTERPRETERS:
                return True
        return False

    @staticmethod
    def _malicious_rationale(
        index: EvidenceIndex,
        pairs: list[tuple[SecurityFinding, SecurityFinding]],
    ) -> str:
        indicators: list[str] = []
        for malicious, _ in pairs:
            indicators.extend(malicious.related_indicators)
        unique = list(dict.fromkeys(indicators))
        return (
            f"{len(pairs)} cross-source pair(s) link an observed malicious indicator "
            f"({', '.join(unique)}) to behaviour findings produced from independent telemetry "
            "records, so the malicious disposition threshold is met. "
            f"{UNCALIBRATED_NOTE}"
        )
