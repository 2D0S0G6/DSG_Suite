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


class FakeGroq:
    """Stand-in for GroqAnalyzer used to test the LLM path without an API."""

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
def fake_groq():
    return FakeGroq()


# --- Agentic-engine fakes ------------------------------------------------------
import json as _json


class _FakeFn:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = _json.dumps(arguments)


class _FakeToolCall:
    def __init__(self, call_id, name, arguments):
        self.id = call_id
        self.type = "function"
        self.function = _FakeFn(name, arguments)


class _FakeMessage:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


def tool_call(call_id, name, **arguments):
    return _FakeMessage(tool_calls=[_FakeToolCall(call_id, name, arguments)])


class FakeGroqAgent(FakeGroq):
    """A scriptable tool-calling stand-in for the agent loop.

    ``script`` is a list of _FakeMessage turns returned in order by
    ``chat_with_tools``; once exhausted it returns a bare 'DONE' message.
    """

    def __init__(self, script=None, available=True):
        super().__init__(available=available)
        if script is None:
            script = [
                tool_call("c1", "get_evidence", form="dom_sinks"),
                tool_call(
                    "c2", "report_finding",
                    type="DOM XSS", severity="high", url="http://test.local/",
                    evidence="innerHTML", description="tainted sink", confidence="high",
                ),
                _FakeMessage(content="DONE"),
            ]
        self._script = script
        self._i = 0

    def chat_with_tools(self, messages, tools=None, tool_choice="auto", **kw):
        if self._i >= len(self._script):
            return _FakeMessage(content="DONE")
        turn = self._script[self._i]
        self._i += 1
        return turn


@pytest.fixture
def fake_agent():
    return FakeGroqAgent()


@pytest.fixture
def collector(fetch):
    """A real, offline RequestsCollector over the in-memory SITE."""
    from pipeline.collectors.base import RequestsCollector

    return RequestsCollector(fetch=fetch)
