"""Shared test fixtures.

Provides an in-memory website and an injectable fetcher so every pipeline stage
runs deterministically with no network access or API keys.
"""

import os
import sys

import pytest

# Make the backend package importable when pytest is run from the repo root.
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


# A tiny site: home page links to /profile, loads /app.js and has an inline
# script.  /app.js contains a DOM XSS sink, a hardcoded secret, an http:// URL
# and an IDOR-shaped endpoint.
SITE = {
    "http://test.local/": (
        200,
        "text/html",
        """
        <html><body>
          <a href="/profile?id=1">Profile</a>
          <a href="/about">About</a>
          <a href="https://evil.example.com/">external</a>
          <script src="/app.js"></script>
          <script>var x = location.hash; document.getElementById('o').innerHTML = x;</script>
        </body></html>
        """,
    ),
    "http://test.local/profile?id=1": (
        200,
        "text/html",
        "<html><body><h1>Profile</h1><form action='/save'><input name='bio'></form></body></html>",
    ),
    "http://test.local/about": (
        200,
        "text/html",
        "<html><body>About us</body></html>",
    ),
    "http://test.local/app.js": (
        200,
        "application/javascript",
        (
            "function render(v){el.innerHTML=v;}"
            "var api_key='SUPERSECRETKEY123456';"
            "fetch('http://test.local/api/v1/users?id=42');"
            "fetch('/api/v1/orders?order=7');"
        ),
    ),
}


@pytest.fixture
def site():
    return dict(SITE)


@pytest.fixture
def fetch(site):
    def _fetch(url):
        return site.get(url)

    return _fetch


class FakeGemini:
    """Stand-in for GeminiAnalyzer used to test the LLM path without an API."""

    def __init__(self, available=True, vulns=None):
        self._available = available
        self._vulns = vulns if vulns is not None else ["IDOR", "Broken Auth"]

    def is_available(self):
        return self._available

    def is_rate_limited(self):
        return False

    def analyze_endpoint(self, endpoint, method="GET", parameters=None, response_sample=None):
        return {
            "endpoint_purpose": "test endpoint",
            "potential_vulnerabilities": self._vulns,
            "risk_level": "high",
        }


@pytest.fixture
def fake_gemini():
    return FakeGemini()
