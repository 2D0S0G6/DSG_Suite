"""Autonomous browser verification of candidate findings.

Analysis (deterministic baseline + the agent) *proposes* findings; this stage
*confirms* the browser-verifiable ones by actually driving Playwright with a
**benign canary** and checking whether it executes.  A DOM/reflected-XSS finding
that fires a marker in a real page is promoted to `confidence=high` with a proof
-of-concept URL; one that does not is kept but flagged `verified=false` (absence
of execution is not proof of safety).

Safety / boundary:
* **Benign only** — the canary sets a unique JS marker (and trips `alert`); it
  never exfiltrates data or performs a destructive action.
* **In-scope, GET-only** — probe URLs are scope-checked; the read-only route guard
  still aborts any state-changing sub-request the page tries to make.
* **Opt-in** — gated by ``config.verify_findings`` (on for the browser/agentic
  preset, off for the lightweight one). No browser -> skipped with a note.

The browser probe is injected (``probe``) so the whole stage is unit-tested
offline with a fake.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Callable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .models import Finding
from .scope import Scope

logger = logging.getLogger("dsg.verify")

# A probe navigates ``target_url`` and returns True if the canary ``nonce``
# executed in the page.
Probe = Callable[[str, str], bool]

# Finding types we know how to confirm in a browser.
_VERIFIABLE = ("dom xss", "reflected xss", "xss")


def _is_verifiable(f: Finding) -> bool:
    return bool(f.url) and f.url.startswith("http") and any(k in f.type.lower() for k in _VERIFIABLE)


def _nonce(f: Finding) -> str:
    """Deterministic per-finding marker (no RNG → reproducible runs)."""
    basis = (f.fingerprint or f.url or f.type)
    return "dsg" + hashlib.sha1(basis.encode("utf-8")).hexdigest()[:10]


def _payload(nonce: str) -> str:
    # Fires for HTML-injection sinks (innerHTML/document.write/insertAdjacentHTML)
    # via the img onerror; also trips alert() for good measure.
    return f"<img src=x onerror=\"window.__dsg_fired='{nonce}';alert('{nonce}')\">"


def _targets(f: Finding, payload: str) -> List[str]:
    """Where to place the canary: the URL fragment, and a known query param."""
    base = f.url.split("#", 1)[0]
    targets = [f"{base}#{payload}"]
    if f.parameter:
        p = urlparse(base)
        params = dict(parse_qsl(p.query, keep_blank_values=True))
        params[f.parameter] = payload
        targets.append(urlunparse(p._replace(query=urlencode(params))))
    return targets


def verify_findings(
    findings: List[Finding],
    scope: Scope,
    config=None,
    probe: Optional[Probe] = None,
) -> Tuple[List[Finding], List[dict]]:
    """Confirm verifiable findings in a browser; annotate them in place.

    Returns ``(findings, notes)`` where ``notes`` is a per-attempt log for the
    report/dashboard.
    """
    verifiable = [f for f in findings if _is_verifiable(f)]
    if not verifiable:
        return findings, [{"note": "no browser-verifiable findings"}]

    owns_probe = probe is None
    if probe is None:
        probe = _default_probe(config, scope)
        if probe is None:
            return findings, [{"note": "verification skipped: no browser available"}]

    notes: List[dict] = []
    try:
        for f in verifiable:
            nonce = _nonce(f)
            payload = _payload(nonce)
            executed, poc = False, ""
            for target in _targets(f, payload):
                if not scope.is_in_scope(target):
                    continue
                try:
                    if probe(target, nonce):
                        executed, poc = True, target.split("#", 1)[0] + "#<canary>"
                        break
                except Exception as exc:  # a bad probe never breaks the run
                    logger.info("probe error on %s: %s", target, exc)
            f.metadata["verified"] = executed
            if executed:
                f.confidence = "high"
                f.metadata["verification"] = {"method": "browser-canary", "executed": True, "poc": poc}
            notes.append({"type": f.type, "url": f.url, "verified": executed})
    finally:
        if owns_probe and hasattr(probe, "close"):
            probe.close()

    confirmed = sum(1 for n in notes if n.get("verified"))
    logger.info("browser verification: %d/%d confirmed", confirmed, len(verifiable))
    return findings, notes


class _PlaywrightProbe:
    """Real browser probe — one browser reused across all attempts."""

    def __init__(self, config, scope: Scope) -> None:
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        self._ctx = self._browser.new_context(ignore_https_errors=True)
        self._scope = scope
        self._nav_timeout = int(getattr(config, "nav_timeout", 15)) * 1000
        if scope.read_only:
            self._ctx.route("**/*", self._route)

    def _route(self, route):
        from .scope import _WRITE_METHODS

        if route.request.method.upper() in _WRITE_METHODS:
            return route.abort()
        return route.continue_()

    def __call__(self, target_url: str, nonce: str) -> bool:
        page = self._ctx.new_page()
        fired = {"v": False}
        page.on("dialog", lambda d: (fired.__setitem__("v", True), d.dismiss()))
        try:
            page.goto(target_url, timeout=self._nav_timeout, wait_until="load")
            page.wait_for_timeout(300)  # let onerror/handlers run
            marker = None
            try:
                marker = page.evaluate("() => window.__dsg_fired || null")
            except Exception:
                pass
            return bool(fired["v"]) or marker == nonce
        except Exception:
            return False
        finally:
            page.close()

    def close(self) -> None:
        for closer in (self._ctx.close, self._browser.close, self._pw.stop):
            try:
                closer()
            except Exception:
                pass


def _default_probe(config, scope: Scope) -> Optional[Probe]:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401

        return _PlaywrightProbe(config, scope)
    except Exception as exc:
        logger.info("verification browser unavailable: %s", exc)
        return None
