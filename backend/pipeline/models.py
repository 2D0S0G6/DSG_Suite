"""Shared data models for the analysis pipeline.

Every stage in the architecture

    URL -> Crawler -> Endpoint discovery -> JS extraction -> Unminify/unbundle
    -> Chunk/context generation -> RAG -> LLM analysis -> Finding normalization
    -> Deduplication -> Validation -> JSON/HTML report

exchanges these light-weight, JSON-serialisable objects.  Keeping them in one
place lets each stage be unit-tested in isolation.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

# Canonical severity ranking (used for sorting / validation).
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
VALID_SEVERITIES = set(SEVERITY_ORDER)
VALID_CONFIDENCE = {"high", "medium", "low"}


@dataclass
class Endpoint:
    """A discovered request target."""

    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    source: str = "crawl"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class JSAsset:
    """A JavaScript source (external file or inline block)."""

    url: str
    content: str
    inline: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Chunk:
    """A retrievable unit of context fed to the RAG / LLM stages."""

    id: str
    source: str          # originating url or file
    kind: str            # "js" | "html" | "endpoint" | "form"
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A normalised security finding.

    Heterogeneous detector output (regex scanners, Gemini, heuristics) is mapped
    onto this single shape by the normalisation stage so that deduplication,
    validation and reporting can treat everything uniformly.
    """

    type: str
    severity: str = "medium"
    title: str = ""
    url: str = ""
    parameter: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    confidence: str = "medium"
    source: str = "scanner"
    fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_fingerprint(self) -> str:
        """Stable identity used for deduplication.

        Two findings collide when they describe the same weakness at the same
        location — type + normalised url + parameter.
        """
        basis = "|".join(
            [
                (self.type or "").strip().lower(),
                _normalise_url(self.url),
                (self.parameter or "").strip().lower(),
            ]
        )
        self.fingerprint = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]
        return self.fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _normalise_url(url: str) -> str:
    """Drop scheme, fragments and trailing slashes so trivially different URLs
    fingerprint identically."""
    if not url:
        return ""
    u = url.strip().lower()
    u = u.split("#", 1)[0]
    for prefix in ("https://", "http://"):
        if u.startswith(prefix):
            u = u[len(prefix):]
            break
    return u.rstrip("/")
