"""Deterministic evidence shaping — raw captures -> AI-ready "forms".

This is the deterministic bridge between collection and reasoning.  It takes the
raw :class:`~pipeline.collectors.base.PageCapture` list and folds it into a small
set of compact, typed inventories — the shape that is *best to hand a model*:

* ``endpoints``        — request targets (crawl + JS-mined + observed XHR)
* ``forms``            — inputs, CSRF-token presence, destructive?
* ``dom_sinks``        — dangerous sink usage in JS/DOM (source -> sink)
* ``network_map``      — third-party calls, mixed content, secrets-in-query, CORS
* ``storage``          — cookies (+flags), storage keys, tokens in storage
* ``security_headers`` — present vs missing per page
* ``secrets``          — where hardcoded secrets were found (values redacted)

Every string that could carry a secret is passed through
:mod:`pipeline.redaction` first, so the model (and the report) only ever see
placeholders.  The same inventories are also emitted as RAG :class:`Chunk`\\ s so
retrieval can pull them alongside code.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List
from urllib.parse import parse_qsl, urlparse

from .collectors.base import PageCapture
from .endpoint_discovery import discover_endpoints, looks_like_api
from .js_extraction import mine_endpoints
from .llm_analysis import DETECTORS
from .models import Chunk
from .redaction import redact, redact_obj, scan_secrets

# Source patterns that feed DOM-XSS sinks (attacker-controllable inputs).
_DOM_SOURCES = ("location.hash", "location.search", "location.href", "document.url", "document.referrer", "window.name")

# Response/request security headers we grade the main document on.
_RECOMMENDED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

# Pull the DOM-XSS sink patterns straight from the shared detector table so the
# deterministic shaping and the heuristic fallback agree on what a "sink" is.
_SINK_PATTERNS = next(
    (d["patterns"] for d in DETECTORS if d["vuln"] == "DOM XSS"), []
)


def _host(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return ""


def _strip_query_values(url: str) -> str:
    """Keep the path + param *names* but drop values (which may be secrets)."""
    try:
        p = urlparse(url)
        names = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        base = f"{p.scheme}://{p.netloc}{p.path}"
        return f"{base}?{'&'.join(names)}" if names else base
    except Exception:
        return url


@dataclass
class Evidence:
    endpoints: List[Dict] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    dom_sinks: List[Dict] = field(default_factory=list)
    network_map: Dict = field(default_factory=dict)
    storage: Dict = field(default_factory=dict)
    security_headers: List[Dict] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    pages: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)

    def form_names(self) -> List[str]:
        return [
            "endpoints",
            "forms",
            "dom_sinks",
            "network_map",
            "storage",
            "security_headers",
            "secrets",
            "pages",
        ]


def _endpoints(captures: List[PageCapture], seed_host: str) -> List[Dict]:
    page_urls = [c.url for c in captures]
    link_urls = [l for c in captures for l in c.links]
    js_eps = mine_endpoints([s for c in captures for s in c.scripts])
    seed = next((c.url for c in captures), "")
    discovered = discover_endpoints(page_urls + link_urls, js_endpoints=js_eps, base_url=seed)

    out: List[Dict] = []
    seen: set = set()
    for ep in discovered:
        key = _strip_query_values(ep.url)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "url": key,
                "method": ep.method,
                "params": ep.params,
                "source": ep.source,
                "is_api": looks_like_api(ep.url),
            }
        )
    # Observed XHR/fetch on the wire that isn't already listed.
    for cap in captures:
        for n in cap.network:
            if n.resource_type in ("xhr", "fetch") or looks_like_api(n.url):
                key = _strip_query_values(n.url)
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "url": key,
                        "method": n.method,
                        "params": [k for k, _ in parse_qsl(urlparse(n.url).query)],
                        "source": "network",
                        "is_api": looks_like_api(n.url),
                    }
                )
    return out


def _forms(captures: List[PageCapture]) -> List[Dict]:
    from .scope import _DESTRUCTIVE_PATTERNS

    out: List[Dict] = []
    for cap in captures:
        for form in cap.forms:
            method = (form.get("method") or "GET").upper()
            action = form.get("action", "")
            out.append(
                {
                    "page": cap.url,
                    "action": _strip_query_values(action),
                    "method": method,
                    "fields": form.get("fields", []),
                    "has_csrf_token": form.get("has_csrf_token", False),
                    "destructive": method in ("POST", "PUT", "PATCH", "DELETE")
                    or bool(_DESTRUCTIVE_PATTERNS.search(action or "")),
                }
            )
    return out


def _dom_sinks(captures: List[PageCapture]) -> List[Dict]:
    import re

    out: List[Dict] = []
    for cap in captures:
        haystacks = [(cap.url, cap.dom)] + [(s.url, s.content) for s in cap.scripts]
        for source_url, content in haystacks:
            if not content:
                continue
            for pattern in _SINK_PATTERNS:
                m = re.search(pattern, content)
                if not m:
                    continue
                lowered = content.lower()
                tainted = any(src in lowered for src in _DOM_SOURCES)
                out.append(
                    {
                        "source_url": source_url,
                        "sink": m.group(0)[:80],
                        "evidence": redact(m.group(0)[:160]),
                        "tainted_source_present": tainted,
                    }
                )
    return out


def _network_map(captures: List[PageCapture], seed_host: str) -> Dict:
    third_party: set = set()
    mixed_content: set = set()
    cors_wildcard: set = set()
    secrets_in_query: List[Dict] = []

    for cap in captures:
        page_https = cap.url.lower().startswith("https://")
        for n in cap.network:
            host = _host(n.url)
            if host and host != seed_host:
                third_party.add(host)
            if page_https and n.url.lower().startswith("http://"):
                mixed_content.add(_strip_query_values(n.url))
            aco = (n.response_headers or {}).get("access-control-allow-origin") or (
                n.response_headers or {}
            ).get("Access-Control-Allow-Origin")
            if aco == "*":
                cors_wildcard.add(host)
            q = urlparse(n.url).query
            if q:
                found = scan_secrets(q)
                if found:
                    secrets_in_query.append(
                        {"url": _strip_query_values(n.url), "kinds": sorted({f["kind"] for f in found})}
                    )
    return {
        "third_party_hosts": sorted(third_party),
        "mixed_content": sorted(mixed_content),
        "cors_wildcard_hosts": sorted(cors_wildcard),
        "secrets_in_query": secrets_in_query,
    }


def _storage(captures: List[PageCapture]) -> Dict:
    cookies: List[Dict] = []
    seen_cookies: set = set()
    local_keys: set = set()
    session_keys: set = set()
    tokens: List[Dict] = []

    for cap in captures:
        for c in cap.cookies:
            name = c.get("name", "")
            if name in seen_cookies:
                continue
            seen_cookies.add(name)
            cookies.append(
                {
                    "name": name,
                    "secure": bool(c.get("secure")),
                    "httpOnly": bool(c.get("httpOnly")),
                    "sameSite": c.get("sameSite", ""),
                }
            )
        for store, keyset in ((cap.local_storage, local_keys), (cap.session_storage, session_keys)):
            for k, v in (store or {}).items():
                keyset.add(k)
                found = scan_secrets(str(v))
                if found:
                    tokens.append({"key": k, "kinds": sorted({f["kind"] for f in found})})
    return {
        "cookies": cookies,
        "local_storage_keys": sorted(local_keys),
        "session_storage_keys": sorted(session_keys),
        "tokens_in_storage": tokens,
    }


def _security_headers(captures: List[PageCapture]) -> List[Dict]:
    out: List[Dict] = []
    for cap in captures:
        if not cap.security_headers and cap.status == 0:
            continue
        present = {k: v for k, v in (cap.security_headers or {}).items() if k != "set-cookie"}
        missing = [h for h in _RECOMMENDED_HEADERS if h not in present]
        out.append({"url": cap.url, "present": sorted(present.keys()), "missing": missing})
    return out


def _secrets(captures: List[PageCapture]) -> List[Dict]:
    out: List[Dict] = []
    for cap in captures:
        for asset in cap.scripts:
            for hit in scan_secrets(asset.content):
                out.append({"url": asset.url, "kind": hit["kind"], "hint": hit["hint"]})
    return out


def _pages(captures: List[PageCapture]) -> List[Dict]:
    return [
        {
            "url": c.url,
            "status": c.status,
            "scripts": len(c.scripts),
            "forms": len(c.forms),
            "links": len(c.links),
            "console_errors": len([m for m in c.console if m.lower().startswith("error")]) + len(c.errors),
        }
        for c in captures
    ]


def shape(captures: List[PageCapture], scope, config=None) -> Evidence:
    """Fold raw captures into the redacted evidence forms."""
    seed_host = scope.hosts[0] if scope.hosts else _host(scope.seed_url)
    ev = Evidence(
        endpoints=_endpoints(captures, seed_host),
        forms=_forms(captures),
        dom_sinks=_dom_sinks(captures),
        network_map=_network_map(captures, seed_host),
        storage=_storage(captures),
        security_headers=_security_headers(captures),
        secrets=_secrets(captures),
        pages=_pages(captures),
    )
    # Final safety net: nothing secret-shaped leaves in any string field.
    return Evidence(**redact_obj(ev.to_dict()))


def baseline_findings(evidence: Evidence) -> List[Dict]:
    """Turn high-signal evidence forms into deterministic raw findings.

    These are *facts* the shaping stage already established (a secret exists here,
    this cookie lacks Secure, this sink is fed by a tainted source), independent of
    the model.  Emitted with ``source="evidence"`` so the agent's reasoning-based
    findings corroborate (and dedup-merge with) them rather than being the only
    thing standing between a real issue and the report.
    """
    out: List[Dict] = []

    for s in evidence.secrets:
        out.append({
            "type": "Hardcoded Secret", "severity": "high", "url": s.get("url", ""),
            "evidence": f"{s.get('kind')} ({s.get('hint')})", "source": "evidence",
            "description": "A credential-shaped value is hardcoded in client-side code.",
            "remediation": "Move secrets server-side and rotate any exposed key.",
            "confidence": "high",
        })

    for sink in evidence.dom_sinks:
        if sink.get("tainted_source_present"):
            out.append({
                "type": "DOM XSS", "severity": "high", "url": sink.get("source_url", ""),
                "evidence": sink.get("evidence", sink.get("sink", "")), "source": "evidence",
                "description": "A dangerous DOM sink appears alongside an attacker-controllable source.",
                "remediation": "Sanitize input or use textContent/safe APIs instead of HTML sinks.",
                "confidence": "medium",
            })

    for form in evidence.forms:
        if form.get("destructive") and not form.get("has_csrf_token"):
            out.append({
                "type": "CSRF", "severity": "medium", "url": form.get("action", ""),
                "evidence": f"{form.get('method')} form without CSRF token", "source": "evidence",
                "description": "A state-changing form has no anti-CSRF token.",
                "remediation": "Add and validate a per-session CSRF token.",
                "confidence": "medium",
            })

    nm = evidence.network_map or {}
    for u in nm.get("mixed_content", []):
        out.append({
            "type": "Insecure Transport", "severity": "medium", "url": u, "source": "evidence",
            "evidence": "http:// resource on an https page", "confidence": "high",
            "description": "Mixed content loaded over plaintext HTTP.",
            "remediation": "Load all sub-resources over HTTPS.",
        })
    for item in nm.get("secrets_in_query", []):
        out.append({
            "type": "Sensitive Data in URL", "severity": "high", "url": item.get("url", ""),
            "evidence": ", ".join(item.get("kinds", [])), "source": "evidence", "confidence": "high",
            "description": "A secret-shaped value is passed in a URL query string.",
            "remediation": "Send credentials in headers/body, never in the URL.",
        })
    for host in nm.get("cors_wildcard_hosts", []):
        out.append({
            "type": "Permissive CORS", "severity": "medium", "url": host, "source": "evidence",
            "evidence": "Access-Control-Allow-Origin: *", "confidence": "high",
            "description": "A response allows any origin via a wildcard CORS policy.",
            "remediation": "Restrict Access-Control-Allow-Origin to trusted origins.",
        })

    storage = evidence.storage or {}
    for cookie in storage.get("cookies", []):
        missing = [f for f in ("secure", "httpOnly") if not cookie.get(f)]
        if missing:
            out.append({
                "type": "Insecure Cookie", "severity": "low", "url": "", "source": "evidence",
                "parameter": cookie.get("name", ""),
                "evidence": f"cookie '{cookie.get('name')}' missing {', '.join(missing)}",
                "description": "A cookie is missing recommended security flags.",
                "remediation": "Set Secure, HttpOnly and SameSite on session cookies.",
                "confidence": "high",
            })
    for tok in storage.get("tokens_in_storage", []):
        out.append({
            "type": "Token in Web Storage", "severity": "medium", "url": "", "source": "evidence",
            "parameter": tok.get("key", ""), "evidence": ", ".join(tok.get("kinds", [])),
            "description": "A token/secret is stored in localStorage/sessionStorage (readable by XSS).",
            "remediation": "Prefer HttpOnly cookies for session tokens.",
            "confidence": "medium",
        })

    for page in evidence.security_headers[:1]:  # seed page only, to avoid noise
        if page.get("missing"):
            out.append({
                "type": "Missing Security Headers", "severity": "low", "url": page.get("url", ""),
                "evidence": ", ".join(page.get("missing", [])), "source": "evidence",
                "description": "Recommended security response headers are absent.",
                "remediation": "Add CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
                "confidence": "high",
            })

    return out


def to_chunks(evidence: Evidence) -> List[Chunk]:
    """Emit each evidence form as a retrievable chunk for the RAG index."""
    import json

    chunks: List[Chunk] = []
    for name in evidence.form_names():
        value = getattr(evidence, name)
        if not value:
            continue
        content = f"EVIDENCE::{name}\n" + json.dumps(value, indent=2)[:4000]
        chunks.append(
            Chunk(id=f"evidence-{name}", source=f"evidence://{name}", kind="evidence", content=content)
        )
    return chunks
