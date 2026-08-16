"""Stage 2 - Endpoint discovery.

Turns crawled URLs (and, later, endpoints mined from JavaScript) into a
deduplicated set of :class:`Endpoint` request targets, capturing HTTP method and
parameter names.
"""

from __future__ import annotations

import re
from typing import Iterable, List
from urllib.parse import parse_qsl, urlparse

from .models import Endpoint

API_PATTERNS = [
    re.compile(r"/api/[a-zA-Z0-9_\-/]+"),
    re.compile(r"/v\d+/[a-zA-Z0-9_\-/]+"),
    re.compile(r"/graphql\b"),
    re.compile(r"/rest/[a-zA-Z0-9_\-/]+"),
]


def _params_of(url: str) -> List[str]:
    parsed = urlparse(url)
    seen: List[str] = []
    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key and key not in seen:
            seen.append(key)
    return seen


def discover_endpoints(
    urls: Iterable[str],
    js_endpoints: Iterable[str] = (),
    base_url: str = "",
) -> List[Endpoint]:
    """Merge crawled URLs and JS-mined endpoint paths into unique endpoints."""
    endpoints: dict = {}

    def _add(url: str, source: str) -> None:
        key = url.split("#", 1)[0].rstrip("/")
        if not key:
            return
        if key not in endpoints:
            endpoints[key] = Endpoint(
                url=url, method="GET", params=_params_of(url), source=source
            )

    for url in urls:
        _add(url, "crawl")

    # JS-mined endpoints are usually bare paths -> resolve against base_url.
    base = ""
    if base_url:
        p = urlparse(base_url)
        base = f"{p.scheme}://{p.netloc}"
    for ep in js_endpoints:
        if ep.startswith("http"):
            _add(ep, "javascript")
        elif base and ep.startswith("/"):
            _add(base + ep, "javascript")

    return list(endpoints.values())


def looks_like_api(url: str) -> bool:
    return any(p.search(url) for p in API_PATTERNS)
