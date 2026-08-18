"""Playwright collector — the real client-side runtime.

Drives headless Chromium to render each in-scope page (executing its JS) and
captures the full client-side surface: post-render DOM, actual loaded JS bodies,
the network log, cookies, ``localStorage``/``sessionStorage``, console output,
forms and links.  This is where "access the client-side code and everything"
actually happens.

Boundary enforcement lives right here at the browser edge:

* **Scope** — only in-scope URLs are ever *navigated*; out-of-scope links are
  never enqueued.
* **Read-only** — a request-router aborts any state-changing sub-request
  (POST/PUT/PATCH/DELETE) while ``scope.read_only`` is set, so rendering a page
  can never mutate the target.  Third-party *GET* sub-resources are observed
  (they inform the network map) but the browser never leaves scope.

Playwright is imported lazily; :meth:`PlaywrightCollector.available` reports
whether the browser stack is actually usable so callers can fall back.
"""

from __future__ import annotations

import logging
from typing import Dict, List

from ..models import JSAsset
from ..scope import _WRITE_METHODS, Scope
from .base import (
    NetworkEntry,
    PageCapture,
    parse_forms,
    parse_links,
)

logger = logging.getLogger("dsg.collector.browser")

# Security response headers we always surface (present or absent is meaningful).
_SEC_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "set-cookie",
]


class PlaywrightCollector:
    """Collector backed by a headless Chromium instance."""

    def __init__(self, nav_timeout_ms: int = 15000, wait_until: str = "networkidle") -> None:
        self.nav_timeout_ms = nav_timeout_ms
        self.wait_until = wait_until

    def available(self) -> bool:
        """True only if Playwright *and* a launchable browser are present."""
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return False
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                browser.close()
            return True
        except Exception as exc:
            logger.info("Playwright present but browser not launchable: %s", exc)
            return False

    def collect(self, scope: Scope, config=None) -> List[PageCapture]:
        from playwright.sync_api import sync_playwright

        nav_timeout = getattr(config, "nav_timeout", None)
        if nav_timeout:
            self.nav_timeout_ms = int(nav_timeout * 1000)
        max_pages = scope.max_pages

        captures: List[PageCapture] = []
        visited: set = set()
        queue: List[str] = [scope.seed_url]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            # Read-only guard: abort any state-changing sub-request.
            def _route(route):
                req = route.request
                if scope.read_only and req.method.upper() in _WRITE_METHODS:
                    return route.abort()
                return route.continue_()

            if scope.read_only:
                context.route("**/*", _route)

            while queue and len(captures) < max_pages:
                url = queue.pop(0)
                if url in visited or not scope.is_in_scope(url):
                    continue
                visited.add(url)
                cap = self._capture_page(context, url)
                captures.append(cap)
                for link in cap.links:
                    if link not in visited and scope.is_in_scope(link):
                        queue.append(link)

            context.close()
            browser.close()

        return captures

    def _capture_page(self, context, url: str) -> PageCapture:
        page = context.new_page()
        network: List[NetworkEntry] = []
        console: List[str] = []
        errors: List[str] = []
        script_bodies: Dict[str, str] = {}
        security_headers: Dict[str, str] = {}
        main_status = {"code": 0}

        def _on_response(response):
            try:
                req = response.request
                entry = NetworkEntry(
                    method=req.method,
                    url=response.url,
                    status=response.status,
                    resource_type=req.resource_type,
                    response_headers=dict(response.headers or {}),
                )
                network.append(entry)
                if response.url == url:
                    main_status["code"] = response.status
                    hdrs = {k.lower(): v for k, v in (response.headers or {}).items()}
                    for h in _SEC_HEADERS:
                        if h in hdrs:
                            security_headers[h] = hdrs[h]
                if req.resource_type == "script":
                    try:
                        script_bodies[response.url] = response.text()
                    except Exception:
                        pass
            except Exception:
                pass

        page.on("response", _on_response)
        page.on("console", lambda m: console.append(f"{m.type}: {m.text}"[:500]))
        page.on("pageerror", lambda e: errors.append(str(e)[:500]))

        cap = PageCapture(url=url)
        try:
            page.goto(url, timeout=self.nav_timeout_ms, wait_until=self.wait_until)
        except Exception as exc:
            errors.append(f"navigation: {exc}")

        try:
            cap.dom = page.content()
        except Exception:
            cap.dom = ""

        # Inline scripts from the rendered DOM + external bodies seen on the wire.
        scripts: List[JSAsset] = []
        try:
            for el in page.query_selector_all("script"):
                src = el.get_attribute("src")
                if src:
                    continue  # captured via network below
                code = el.inner_text() or ""
                if code.strip():
                    scripts.append(JSAsset(url=f"{url}#inline", content=code, inline=True))
        except Exception:
            pass
        for js_url, body in script_bodies.items():
            if body and body.strip():
                scripts.append(JSAsset(url=js_url, content=body, inline=False))
        cap.scripts = scripts

        cap.forms = parse_forms(cap.dom, url)
        cap.links = parse_links(cap.dom, url)
        cap.network = network
        cap.console = console
        cap.errors = errors
        cap.security_headers = security_headers
        cap.status = main_status["code"]

        # Runtime state.
        try:
            cap.cookies = context.cookies()
        except Exception:
            pass
        try:
            cap.local_storage = page.evaluate(
                "() => Object.fromEntries(Object.entries(window.localStorage))"
            ) or {}
        except Exception:
            pass
        try:
            cap.session_storage = page.evaluate(
                "() => Object.fromEntries(Object.entries(window.sessionStorage))"
            ) or {}
        except Exception:
            pass

        page.close()
        return cap
