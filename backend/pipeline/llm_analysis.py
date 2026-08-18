"""Stage 7 - LLM analysis.

For each vulnerability class we phrase a natural-language query, use the RAG
retriever to pull the most relevant chunks, and analyse them:

* If a Groq analyzer is available, the retrieved context is sent to it.
* Otherwise a set of deterministic heuristic detectors run over the same
  retrieved context, so the pipeline (and its tests) yield findings offline with
  no API key.

Both paths emit *raw* finding dicts; shape normalisation happens in the next
stage.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .models import Chunk
from .rag import TfidfRetriever

# (query, {detector metadata}) — the query drives retrieval; the detector runs
# over what comes back.
DETECTORS = [
    {
        "vuln": "DOM XSS",
        "query": "innerHTML document.write eval outerHTML insertAdjacentHTML dangerouslySetInnerHTML location.hash sink",
        "severity": "high",
        "patterns": [
            r"\.innerHTML\s*=",
            r"document\.write\s*\(",
            r"\beval\s*\(",
            r"insertAdjacentHTML",
            r"dangerouslySetInnerHTML",
        ],
        "remediation": "Avoid writing untrusted data to HTML sinks; use textContent or a sanitizer.",
    },
    {
        "vuln": "Hardcoded Secret",
        "query": "api_key apiKey secret token password bearer authorization aws access key credentials",
        "severity": "critical",
        "patterns": [
            r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            r"AKIA[0-9A-Z]{16}",
            r"Bearer\s+[A-Za-z0-9\-_\.]{20,}",
        ],
        "remediation": "Never ship secrets in client-side code; move them server-side and rotate exposed keys.",
    },
    {
        "vuln": "Insecure Transport",
        "query": "http:// mixed content insecure request fetch xhr endpoint",
        "severity": "medium",
        "patterns": [r"http://[^\s'\"]+"],
        "remediation": "Use HTTPS for all requests to prevent interception and mixed-content issues.",
    },
    {
        "vuln": "Potential IDOR",
        "query": "api endpoint numeric id user_id account order object reference parameter",
        "severity": "high",
        "patterns": [r"[?&](?:id|user_id|account|order|uid)=\d+"],
        "remediation": "Enforce object-level authorization on every request; do not trust client-supplied IDs.",
    },
]


def _first_evidence(pattern: str, text: str) -> Optional[str]:
    m = re.search(pattern, text, re.IGNORECASE)
    if not m:
        return None
    snippet = m.group(0)
    return snippet[:200]


def _heuristic_findings(detector: Dict[str, Any], chunks: List[Chunk]) -> List[Dict]:
    findings: List[Dict] = []
    for chunk in chunks:
        # Evidence chunks describe findings (they contain sink names, secret kinds,
        # etc.) and are meant for the agent's tools — regexing them would flag the
        # description itself. Skip them here; the deterministic baseline already
        # turns evidence into findings.
        if chunk.kind == "evidence":
            continue
        for pattern in detector["patterns"]:
            evidence = _first_evidence(pattern, chunk.content)
            if evidence:
                findings.append(
                    {
                        "type": detector["vuln"],
                        "severity": detector["severity"],
                        "url": chunk.source,
                        "evidence": evidence,
                        "description": f"{detector['vuln']} indicator found in {chunk.kind} context.",
                        "remediation": detector["remediation"],
                        "confidence": "medium",
                        "source": "heuristic-rag",
                    }
                )
                break  # one hit per chunk per detector is enough
    return findings


def _groq_findings(
    detector: Dict[str, Any], chunks: List[Chunk], groq
) -> List[Dict]:
    context = "\n\n".join(c.content[:800] for c in chunks[:4])
    if not context.strip():
        return []
    try:
        analysis = groq.analyze_endpoint(
            endpoint=chunks[0].source if chunks else "",
            method="GET",
            parameters=[],
            response_sample=context,
        )
    except Exception:
        return []

    findings: List[Dict] = []
    for vuln in analysis.get("potential_vulnerabilities", []) if isinstance(analysis, dict) else []:
        findings.append(
            {
                "type": f"{detector['vuln']}: {vuln}",
                "severity": analysis.get("risk_level", detector["severity"]),
                "url": chunks[0].source if chunks else "",
                "evidence": context[:200],
                "description": analysis.get("endpoint_purpose", ""),
                "remediation": detector["remediation"],
                "confidence": "medium",
                "source": "groq-rag",
            }
        )
    return findings


def analyze(
    retriever: TfidfRetriever,
    groq=None,
    top_k: int = 6,
) -> List[Dict]:
    """Run every detector via retrieval-augmented analysis and return raw findings.

    ``groq`` may be any object exposing ``is_available()`` and
    ``analyze_endpoint(...)``; when absent or unavailable, heuristics are used.
    """
    use_groq = bool(groq) and getattr(groq, "is_available", lambda: False)()
    raw: List[Dict] = []

    for detector in DETECTORS:
        relevant = retriever.retrieve(detector["query"], top_k=top_k)
        if not relevant:
            continue
        if use_groq:
            found = _groq_findings(detector, relevant, groq)
            # Heuristics still run as a safety net if the model returns nothing.
            raw.extend(found or _heuristic_findings(detector, relevant))
        else:
            raw.extend(_heuristic_findings(detector, relevant))

    return raw
