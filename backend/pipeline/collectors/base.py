"""Capture data model + non-browser collectors.

:class:`PageCapture` is the single shape every collector emits and every
downstream stage (evidence shaping, chunking) consumes, so the Playwright and
offline paths are interchangeable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..models import JSAsset
from ..scope import Scope

# A fetch returns (status_code, content_type, text) or None — same contract the
# crawler already uses, so an injected offline fetcher works unchanged.
FetchResult = Optional[Tuple[int, str, str]]
Fetcher = Callable[[str], FetchResult]


@dataclass
class NetworkEntry:
    """One request/response observed while a page loaded."""

    method: str
    url: str
    status: int = 0
    resource_type: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PageCapture:
    """Everything captured for a single page."""

    url: str
    status: int = 0
    dom: str = ""                                    # rendered HTML (post-JS for Playwright)
    scripts: List[JSAsset] = field(default_factory=list)
    network: List[NetworkEntry] = field(default_factory=list)
    cookies: List[Dict] = field(default_factory=list)
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    console: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)  # {action, method, fields:[{name,type}]}
    links: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["scripts"] = [s.to_dict() for s in self.scripts]
        d["network"] = [n.to_dict() for n in self.network]
        return d


# --- shared HTML parsing helpers (used by the offline collector and reused by
#     the Playwright collector for the rendered DOM) -----------------------------

def parse_forms(html: str, page_url: str) -> List[Dict]:
    soup = BeautifulSoup(html or "", "html.parser")
    forms: List[Dict] = []
    for form in soup.find_all("form"):
        fields = []
        for el in form.find_all(["input", "textarea", "select"]):
            name = el.get("name")
            if name:
                fields.append({"name": name, "type": el.get("type", el.name)})
        action = urljoin(page_url, (form.get("action") or "").strip() or page_url)
        forms.append(
            {
                "action": action,
                "method": (form.get("method") or "GET").upper(),
                "fields": fields,
                "has_csrf_token": any(
                    "csrf" in (f["name"] or "").lower() or "token" in (f["name"] or "").lower()
                    for f in fields
                ),
            }
        )
    return forms


def parse_links(html: str, page_url: str) -> List[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    links: List[str] = []
    for tag in soup.find_all("a", href=True):
        href = (tag.get("href") or "").strip()
        if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        full = urljoin(page_url, href).split("#", 1)[0]
        if full.startswith("http"):
            links.append(full)
    return links


def extract_scripts(html: str, page_url: str, fetch: Fetcher, seen: set) -> List[JSAsset]:
    """External ``<script src>`` (fetched, de-duped via ``seen``) + inline blocks."""
    soup = BeautifulSoup(html or "", "html.parser")
    scripts: List[JSAsset] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            js_url = urljoin(page_url, src)
            if js_url in seen:
                continue
            seen.add(js_url)
            result = fetch(js_url)
            if result and result[0] == 200 and result[2]:
                scripts.append(JSAsset(url=js_url, content=result[2], inline=False))
        else:
            code = tag.string or tag.text or ""
            if code.strip():
                scripts.append(JSAsset(url=f"{page_url}#inline", content=code, inline=True))
    return scripts


class RequestsCollector:
    """Offline/degraded collector over an injected ``fetch`` (no JS execution).

    Performs a bounded, in-scope BFS.  Rendered DOM == raw HTML; network log,
    storage and console are unavailable and left empty.  This is the graceful
    fallback when Playwright is absent and the workhorse for offline tests.
    """

    def __init__(self, fetch: Optional[Fetcher] = None) -> None:
        self.fetch = fetch  # resolved lazily so importing never needs requests

    def _resolve_fetch(self, timeout: int) -> Fetcher:
        if self.fetch:
            return self.fetch
        from ..crawler import default_fetch

        return default_fetch(timeout)

    def collect(self, scope: Scope, config=None) -> List[PageCapture]:
        timeout = getattr(config, "request_timeout", 10)
        max_pages = scope.max_pages
        fetch = self._resolve_fetch(timeout)

        seen_scripts: set = set()
        visited: set = set()
        ordered: List[str] = []
        queue: List[str] = [scope.seed_url]
        captures: List[PageCapture] = []

        while queue and len(captures) < max_pages:
            url = queue.pop(0)
            if url in visited or not scope.is_in_scope(url):
                continue
            visited.add(url)
            ordered.append(url)

            result = fetch(url)
            if not result:
                captures.append(PageCapture(url=url, status=0))
                continue
            status, content_type, text = result
            is_html = "html" in (content_type or "").lower()
            cap = PageCapture(
                url=url,
                status=status,
                dom=text if is_html else "",
            )
            if is_html and status == 200:
                cap.scripts = extract_scripts(text, url, fetch, seen_scripts)
                cap.forms = parse_forms(text, url)
                cap.links = parse_links(text, url)
                for link in cap.links:
                    if link not in visited and scope.is_in_scope(link):
                        queue.append(link)
            captures.append(cap)

        return captures


class StaticCollector:
    """Returns a fixed list of captures — for unit tests of the analysis path."""

    def __init__(self, captures: List[PageCapture]) -> None:
        self._captures = captures

    def collect(self, scope: Scope, config=None) -> List[PageCapture]:
        return list(self._captures)


def default_collector(prefer_browser: bool = True):
    """Pick the best available collector.

    Tries Playwright first (real client-side runtime); falls back to the
    ``requests``-based collector if the browser stack is unavailable.
    """
    if prefer_browser:
        try:
            from .browser import PlaywrightCollector

            collector = PlaywrightCollector()
            if collector.available():
                return collector
        except Exception:
            pass
    return RequestsCollector()
