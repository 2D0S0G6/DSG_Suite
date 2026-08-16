"""Stage 10 - Validation.

Final quality gate before reporting.  Drops structurally invalid findings
(missing type, or neither a URL nor evidence to anchor them), coerces any stray
severity/confidence values, and optionally filters out low-confidence noise.

Returns the accepted findings plus the rejected ones (with a reason) so nothing
disappears silently — the caller can log or surface what was filtered.
"""

from __future__ import annotations

from typing import List, Tuple

from .models import VALID_CONFIDENCE, VALID_SEVERITIES, Finding


def _reason(finding: Finding) -> str:
    if not finding.type or finding.type.lower() == "unknown":
        return "missing or unknown finding type"
    if not finding.url and not finding.evidence:
        return "finding has no location or evidence to anchor it"
    return ""


def validate(
    findings: List[Finding], drop_low_confidence: bool = False
) -> Tuple[List[Finding], List[dict]]:
    accepted: List[Finding] = []
    rejected: List[dict] = []

    for finding in findings:
        reason = _reason(finding)
        if reason:
            rejected.append({"finding": finding.to_dict(), "reason": reason})
            continue

        # Coerce any values that slipped past normalisation.
        if finding.severity not in VALID_SEVERITIES:
            finding.severity = "medium"
        if finding.confidence not in VALID_CONFIDENCE:
            finding.confidence = "medium"

        if drop_low_confidence and finding.confidence == "low":
            rejected.append(
                {"finding": finding.to_dict(), "reason": "below confidence threshold"}
            )
            continue

        accepted.append(finding)

    return accepted, rejected
