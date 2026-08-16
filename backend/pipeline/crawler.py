"""Stage 1 - Crawler.

Breadth-first, same-domain crawl starting from a single URL.  The HTTP fetch is
injected (``fetch`` callable) so the crawl logic can be unit-tested against an
in-memory site with no network access.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

# A fetch returns (status_code, content_type, text) or None on failure.
FetchResult = Optional[Tuple[int, str, str]]
Fetcher = Callable[[str], FetchResult]


def default_fetch(timeout: int = 10) -> Fetcher:
    """Build a real network fetcher lazily so importing this module never
    requires the ``requests``/session stack (keeps tests light)."""

    def _fetch(url: str) -> FetchResult:
        try:
            from payload_tester import HEADERS, session

            resp = session.get(url, headers=HEADERS, timeout=timeout)
            return (
                resp.status_code,
                resp.headers.get("Content-Type", ""),
                resp.text,
            )
        except Exception:
            return None

    return _fetch


def get_root_domain(netloc: str) -> str:
    parts = netloc.split(":")[0].split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return netloc


def is_same_domain(url1: str, url2: str) -> bool:
    try:
        return get_root_domain(urlparse(url1).netloc) == get_root_domain(
            urlparse(url2).netloc
        )
    except Exception:
        return False


def crawl(
    start_url: str,
    fetch: Optional[Fetcher] = None,
    max_depth: int = 2,
    max_links: int = 50,
    same_domain: bool = True,
) -> List[str]:
    """Return the list of same-domain URLs reachable from ``start_url``.

    The start URL is always included as the first element.
    """
    fetch = fetch or default_fetch()

    visited: set = set()
    ordered: List[str] = []
    to_visit: List[Tuple[str, int]] = [(start_url, 0)]

    while to_visit:
        url, depth = to_visit.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        ordered.append(url)

        if len(ordered) >= max_links:
            break

        result = fetch(url)
        if not result:
            continue
        status, content_type, text = result
        if status != 200 or "html" not in content_type.lower():
            continue

        soup = BeautifulSoup(text, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = (tag.get("href") or "").strip()
            if not href or href.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            full = urljoin(url, href).split("#", 1)[0]
            if not full.startswith("http"):
                continue
            if same_domain and not is_same_domain(start_url, full):
                continue
            if full not in visited and full not in dict(to_visit):
                to_visit.append((full, depth + 1))

    return ordered
