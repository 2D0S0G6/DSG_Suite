"""Stage 8 - Finding normalisation.

Detectors across the codebase emit dicts with wildly different key names
(``endpoint`` vs ``url``, ``risk_level`` vs ``severity``, ``explanation`` vs
``description``).  This stage maps any of them onto the canonical
:class:`Finding` shape and normalises the severity/confidence vocabularies.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .models import VALID_CONFIDENCE, VALID_SEVERITIES, Finding

# Candidate source keys, in priority order, for each Finding field.
_URL_KEYS = ("url", "endpoint", "location", "path")
_SEVERITY_KEYS = ("severity", "risk_level", "risk", "impact")
_DESC_KEYS = ("description", "explanation", "analysis", "ai_analysis", "notes")
_EVIDENCE_KEYS = ("evidence", "poc", "proof_of_concept")
_PARAM_KEYS = ("parameter", "param", "form_field")

_SEVERITY_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "high": "high",
    "med": "medium",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def _pick(raw: Dict[str, Any], keys: Iterable[str], default: str = "") -> str:
    for key in keys:
        val = raw.get(key)
        if val:
            return str(val)
    return default


def normalize_severity(value: str) -> str:
    v = (value or "").strip().lower()
    v = _SEVERITY_ALIASES.get(v, v)
    return v if v in VALID_SEVERITIES else "medium"


def normalize_confidence(value: str) -> str:
    v = (value or "").strip().lower()
    return v if v in VALID_CONFIDENCE else "medium"


def normalize_one(raw: Dict[str, Any]) -> Finding:
    finding = Finding(
        type=str(raw.get("type") or raw.get("vuln") or "Unknown").strip(),
        severity=normalize_severity(_pick(raw, _SEVERITY_KEYS, "medium")),
        title=str(raw.get("title") or raw.get("name") or raw.get("type") or "").strip(),
        url=_pick(raw, _URL_KEYS),
        parameter=_pick(raw, _PARAM_KEYS),
        evidence=_pick(raw, _EVIDENCE_KEYS),
        description=_pick(raw, _DESC_KEYS),
        remediation=_pick(raw, ("remediation", "fix", "mitigation")),
        confidence=normalize_confidence(_pick(raw, ("confidence",), "medium")),
        source=str(raw.get("source") or "scanner"),
    )
    if not finding.title:
        finding.title = finding.type
    finding.compute_fingerprint()
    return finding


def normalize(raw_findings: Iterable[Dict[str, Any]]) -> List[Finding]:
    return [normalize_one(raw) for raw in raw_findings if raw]
