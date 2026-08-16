"""Stage 3 - JS extraction.

Given HTML pages, collect JavaScript sources: external ``<script src>`` files
(fetched) and inline ``<script>`` blocks.  Also mines API-endpoint paths from the
raw JS so endpoint discovery can be enriched.

The HTTP fetch is injected for testability.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .endpoint_discovery import API_PATTERNS
from .models import JSAsset

FetchResult = Optional[Tuple[int, str, str]]
Fetcher = Callable[[str], FetchResult]


def default_fetch(timeout: int = 10) -> Fetcher:
    def _fetch(url: str) -> FetchResult:
        try:
            from payload_tester import HEADERS, session

            resp = session.get(url, headers=HEADERS, timeout=timeout)
            return resp.status_code, resp.headers.get("Content-Type", ""), resp.text
        except Exception:
            return None

    return _fetch


def extract_js_assets(
    pages: Dict[str, str],
    fetch: Optional[Fetcher] = None,
) -> List[JSAsset]:
    """Return JS assets found across the given ``{url: html}`` pages.

    External scripts are de-duplicated by URL so a shared bundle is fetched once.
    """
    fetch = fetch or default_fetch()
    assets: List[JSAsset] = []
    seen_external: set = set()

    for page_url, html in pages.items():
        soup = BeautifulSoup(html or "", "html.parser")

        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                js_url = urljoin(page_url, src)
                if js_url in seen_external:
                    continue
                seen_external.add(js_url)
                result = fetch(js_url)
                if result and result[0] == 200 and result[2]:
                    assets.append(JSAsset(url=js_url, content=result[2], inline=False))
            else:
                code = tag.string or tag.text or ""
                if code.strip():
                    assets.append(
                        JSAsset(url=f"{page_url}#inline", content=code, inline=True)
                    )

    return assets


def mine_endpoints(assets: List[JSAsset]) -> List[str]:
    """Regex-mine API endpoint paths from JS content."""
    found: set = set()
    for asset in assets:
        for pattern in API_PATTERNS:
            found.update(pattern.findall(asset.content))
    return sorted(found)
