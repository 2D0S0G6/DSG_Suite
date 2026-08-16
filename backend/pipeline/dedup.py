"""Stage 9 - Deduplication.

Collapses findings that share a fingerprint (same type + location + parameter).
When duplicates merge we keep the highest severity/confidence and union the
contributing detector sources, so a finding corroborated by both a regex scanner
and the LLM is reported once but marked more confident.
"""

from __future__ import annotations

from typing import List

from .models import SEVERITY_ORDER, Finding

_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def _stronger_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b


def _stronger_confidence(a: str, b: str) -> str:
    return a if _CONFIDENCE_ORDER.get(a, 0) >= _CONFIDENCE_ORDER.get(b, 0) else b


def deduplicate(findings: List[Finding]) -> List[Finding]:
    merged: dict = {}
    for finding in findings:
        fp = finding.fingerprint or finding.compute_fingerprint()
        if fp not in merged:
            # Track sources as a set inside metadata for merge bookkeeping.
            finding.metadata.setdefault("sources", set()).add(finding.source)
            merged[fp] = finding
            continue

        existing = merged[fp]
        existing.severity = _stronger_severity(existing.severity, finding.severity)
        existing.confidence = _stronger_confidence(
            existing.confidence, finding.confidence
        )
        existing.metadata.setdefault("sources", {existing.source}).add(finding.source)
        # Corroboration by an independent source raises confidence.
        if finding.source != existing.source:
            existing.confidence = _stronger_confidence(existing.confidence, "high")
        if not existing.evidence and finding.evidence:
            existing.evidence = finding.evidence
        merged[fp] = existing

    result = list(merged.values())
    # Serialise the source set back to a sorted list for JSON friendliness.
    for finding in result:
        srcs = finding.metadata.get("sources")
        if isinstance(srcs, set):
            finding.metadata["sources"] = sorted(srcs)
    result.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return result
