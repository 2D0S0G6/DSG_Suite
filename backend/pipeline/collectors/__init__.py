"""Deterministic client-side collection.

A *collector* turns a seed URL (bounded by a :class:`~pipeline.scope.Scope`) into
a list of :class:`PageCapture` objects — the raw, per-page client-side surface
(rendered DOM, loaded JS, network log, storage, forms).  Collection is entirely
deterministic; the agent never drives it.

Three implementations, same interface (``collect(scope, config) -> [PageCapture]``):

* :class:`PlaywrightCollector` — a real headless browser (executes JS, sees the
  runtime).  The default for live runs; imported lazily so the package works
  without Playwright installed.
* :class:`RequestsCollector` — an offline/degraded fallback over an injected
  ``fetch`` (no JS execution): rendered DOM == raw HTML.  Used in CI/tests and
  whenever a browser is unavailable.
* :class:`StaticCollector` — returns pre-built captures verbatim (unit tests).
"""

from __future__ import annotations

from .base import (
    NetworkEntry,
    PageCapture,
    RequestsCollector,
    StaticCollector,
    default_collector,
)

__all__ = [
    "PageCapture",
    "NetworkEntry",
    "RequestsCollector",
    "StaticCollector",
    "default_collector",
]
