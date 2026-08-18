"""Scanner entry points — thin wrappers over the one unified pipeline.

The original monolithic ``scan_url()`` and the separate combined engine are gone:
their active detectors (context-aware XSS + 4-family SQLi via ``payload_tester``,
IDOR via ``idor_scanner``, SSRF / open-redirect) now run as the pipeline's
**active-testing stage** (``pipeline/active.py``). One engine, three presets.

* ``scan_url``          — full active scan over the ``requests`` collector
                          (legacy-compatible payload: findings bucketed by type).
* ``scan_url_pipeline`` — lightweight: analysis only, no active payloads.
* ``scan_url_agentic``  — browser collection + agent + active testing + browser
                          verification, and writes ``reports/dashboard.html``.
"""

from __future__ import annotations

from groq_analyzer import GroqAnalyzer


def _groq():
    g = GroqAnalyzer()
    return g if g.is_available() else None


def scan_url(url):
    """Full active scan (requests collection + active payload testing).

    Returns the pipeline payload; findings are bucketed by type
    (``xss_vulnerabilities``, ``sql_vulnerabilities``, ``idor_vulnerabilities``,
    ``ssrf`` …) so existing API/report consumers keep working.
    """
    from pipeline import Pipeline, PipelineConfig

    cfg = PipelineConfig.from_env()
    cfg.active_testing = True
    return Pipeline(config=cfg, groq=_groq()).run(url)


def scan_url_pipeline(url):
    """Lightweight preset: requests collection + agent-or-heuristic analysis, no
    active payloads. ``scan_url_agentic`` is the same pipeline with the browser
    and active testing turned on."""
    from pipeline import Pipeline, PipelineConfig

    return Pipeline(config=PipelineConfig.from_env(), groq=_groq()).run(url)


def scan_url_agentic(url):
    """Full client-side preset: real browser collection, the bounded Groq agent,
    active payload testing, and autonomous browser verification. Writes the
    standard reports plus ``reports/dashboard.html``."""
    from pipeline import Pipeline, PipelineConfig

    cfg = PipelineConfig.from_env()
    cfg.prefer_browser = True
    cfg.verify_findings = True
    cfg.active_testing = True
    return Pipeline(config=cfg, groq=_groq()).run(url)
