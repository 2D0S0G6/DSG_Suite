"""Active-testing stage — confirm server-side bugs with real payloads.

The deterministic/agent analysis *proposes*; this stage actively *tests* the
in-scope, non-destructive request targets the pipeline already discovered
(evidence endpoints + forms) and confirms exploitable ones:

* **Reflected XSS / SQLi** — `payload_tester` (context-aware XSS, 4-family SQLi)
* **IDOR** — `idor_scanner` (numeric-ID mutation + response diff)
* **SSRF / Open redirect** — localhost / off-site reflection probes

Findings enter the same ``normalize -> dedup -> validate`` backbone with
``source="active"``, so an actively-confirmed SQLi and an agent's "this looks
injectable" merge on one fingerprint and boost confidence.

Because it sends payloads it is **opt-in** (``config.active_testing``) and stays
inside the boundary: only in-scope, non-destructive targets, bounded by
``active_max_targets``.  The detector callables are **injected**, so the stage is
unit-tested offline with no network.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .scope import Scope

logger = logging.getLogger("dsg.active")

# Params worth guessing when an endpoint exposes none, so the detectors still
# have something to probe. Kept small to bound request volume.
_DEFAULT_TEST_PARAMS = ["id", "q", "search", "url", "redirect", "next", "file", "page"]

_SSRF_PARAMS = ("url", "uri", "path", "endpoint", "target", "redirect", "dest")
_REDIRECT_PARAMS = ("redirect", "url", "next", "return", "dest", "destination", "rurl")


def _set_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    params = dict(parse_qsl(p.query, keep_blank_values=True))
    params[name] = value
    return urlunparse(p._replace(query=urlencode(params)))


# --- default detectors: thin wrappers over the existing leaf modules ----------

def _default_xss(url, params, method="get", data=None):
    from payload_tester import test_xss

    return test_xss(url, params, method, data) or []


def _default_sqli(url, params, method="get", data=None):
    from payload_tester import test_error_sql, test_sqli

    out = test_sqli(url, params, method, data) or []
    try:
        out += test_error_sql(url, params, method=method, data=data) or []
    except Exception:
        pass
    return out


def _default_idor(url, params=None):
    from idor_scanner import IDORScanner

    try:
        return IDORScanner().test_idor(url) or []
    except Exception:
        return []


def _default_ssrf(url, params=None):
    from payload_tester import HEADERS, session

    names = params or [k for k, _ in parse_qsl(urlparse(url).query)]
    out: List[Dict] = []
    for name in names:
        if name.lower() not in _SSRF_PARAMS and not name.lower().endswith("url"):
            continue
        target = _set_param(url, name, "http://127.0.0.1")
        try:
            r = session.get(target, headers=HEADERS, timeout=10, verify=False)
            if "127.0.0.1" in (r.text or "") or "127.0.0.1" in (r.url or ""):
                out.append({
                    "type": "SSRF", "url": target, "parameter": name,
                    "evidence": "localhost URL reflected or requested", "severity": "high",
                    "explanation": "A parameter appears to accept arbitrary URLs (server-side request forgery).",
                    "remediation": "Validate URLs and restrict outbound requests to an allow-list.",
                })
        except Exception:
            pass
    return out


def _default_redirect(url, params=None):
    from payload_tester import HEADERS, session

    names = params or [k for k, _ in parse_qsl(urlparse(url).query)]
    out: List[Dict] = []
    for name in names:
        if name.lower() not in _REDIRECT_PARAMS and not name.lower().endswith("url"):
            continue
        target = _set_param(url, name, "https://evil.example")
        try:
            r = session.get(target, headers=HEADERS, timeout=8, verify=False, allow_redirects=False)
            if "evil.example" in (r.headers.get("Location", "") or ""):
                out.append({
                    "type": "Open Redirect", "url": target, "parameter": name,
                    "evidence": r.headers.get("Location", ""), "severity": "high",
                    "explanation": "A redirect destination is reflected from a parameter without validation.",
                    "remediation": "Validate redirect targets against an allow-list or use relative paths.",
                })
        except Exception:
            pass
    return out


class ActiveTester:
    """Runs the active detectors over evidence targets. Detectors are injected."""

    def __init__(
        self,
        config=None,
        xss: Optional[Callable] = None,
        sqli: Optional[Callable] = None,
        idor: Optional[Callable] = None,
        ssrf: Optional[Callable] = None,
        redirect: Optional[Callable] = None,
    ) -> None:
        self.config = config
        self.xss = xss or _default_xss
        self.sqli = sqli or _default_sqli
        self.idor = idor or _default_idor
        self.ssrf = ssrf or _default_ssrf
        self.redirect = redirect or _default_redirect

    def _tag(self, findings) -> List[Dict]:
        out = []
        for f in findings or []:
            if isinstance(f, dict):
                f = dict(f)
                f["source"] = "active"
                out.append(f)
        return out

    def run(self, evidence, scope: Scope) -> List[Dict]:
        cap = getattr(self.config, "active_max_targets", 15)
        raw: List[Dict] = []
        tested = 0

        # GET endpoints with (real or guessed) params → all detectors.
        for ep in evidence.endpoints:
            if tested >= cap:
                break
            url = ep.get("url", "")
            if not scope.is_in_scope(url) or scope.is_destructive(ep.get("method", "GET"), url):
                continue
            params = ep.get("params") or _DEFAULT_TEST_PARAMS
            tested += 1
            for detector in (self.xss, self.sqli, self.idor, self.ssrf, self.redirect):
                try:
                    raw += self._tag(detector(url, params))
                except Exception as exc:
                    logger.info("active detector error on %s: %s", url, exc)

        # Non-destructive forms → reflected XSS / SQLi on their fields.
        for form in evidence.forms:
            if tested >= cap or form.get("destructive"):
                continue
            url = form.get("action", "")
            fields = [f.get("name") for f in form.get("fields", []) if f.get("name")]
            if not fields or not scope.is_in_scope(url):
                continue
            method = (form.get("method") or "GET").lower()
            tested += 1
            for detector in (self.xss, self.sqli):
                try:
                    raw += self._tag(detector(url, fields, method))
                except Exception as exc:
                    logger.info("active form detector error on %s: %s", url, exc)

        logger.info("active testing probed %d targets → %d raw findings", tested, len(raw))
        return raw
