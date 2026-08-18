"""Offline collector: bounded, in-scope crawl over the injected fetch."""

from pipeline.collectors.base import PageCapture, StaticCollector
from pipeline.scope import Scope


def test_requests_collector_stays_in_scope(collector):
    caps = collector.collect(Scope.from_seed("http://test.local/"))
    urls = [c.url for c in caps]
    assert "http://test.local/" in urls
    assert all("evil.example.com" not in u for u in urls)  # external link never followed


def test_requests_collector_captures_scripts_and_forms(collector):
    caps = collector.collect(Scope.from_seed("http://test.local/"))
    home = next(c for c in caps if c.url == "http://test.local/")
    assert any(s.url.endswith("/app.js") for s in home.scripts)  # external JS fetched
    profile = next(c for c in caps if "profile" in c.url)
    assert profile.forms and profile.forms[0]["fields"]


def test_max_pages_cap_is_enforced(collector):
    caps = collector.collect(Scope.from_seed("http://test.local/", max_pages=1))
    assert len(caps) == 1


def test_static_collector_returns_verbatim():
    given = [PageCapture(url="http://x/", status=200, dom="<html></html>")]
    assert StaticCollector(given).collect(Scope.from_seed("http://x/")) == given
