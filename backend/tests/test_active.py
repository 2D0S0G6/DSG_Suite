"""Active-testing stage (offline: injected detector callables)."""

from pipeline import PipelineConfig
from pipeline.active import ActiveTester
from pipeline.orchestrator import Pipeline
from pipeline.scope import Scope


class _Evidence:
    """Minimal stand-in exposing the fields ActiveTester reads."""

    def __init__(self, endpoints=None, forms=None):
        self.endpoints = endpoints or []
        self.forms = forms or []


def _ep(url, params=None, method="GET"):
    return {"url": url, "params": params or [], "method": method}


def test_runs_all_detectors_on_in_scope_endpoint():
    seen = {"xss": 0, "sqli": 0, "idor": 0, "ssrf": 0, "redirect": 0}

    def mk(kind):
        def _d(url, params, *a, **k):
            seen[kind] += 1
            return [{"type": kind.upper(), "url": url, "parameter": (params or ["x"])[0], "severity": "high"}]
        return _d

    tester = ActiveTester(
        config=PipelineConfig(),
        xss=mk("xss"), sqli=mk("sqli"), idor=mk("idor"), ssrf=mk("ssrf"), redirect=mk("redirect"),
    )
    ev = _Evidence(endpoints=[_ep("http://test.local/api?id=1", ["id"])])
    raw = tester.run(ev, Scope.from_seed("http://test.local/"))

    assert all(v == 1 for v in seen.values())        # every detector ran once
    assert raw and all(f["source"] == "active" for f in raw)


def test_skips_out_of_scope_and_destructive():
    calls = []
    probe = lambda url, params, *a, **k: calls.append(url) or []
    tester = ActiveTester(config=PipelineConfig(), xss=probe, sqli=probe, idor=probe, ssrf=probe, redirect=probe)
    ev = _Evidence(endpoints=[
        _ep("http://evil.example.com/api?id=1", ["id"]),        # out of scope
        _ep("http://test.local/account/delete?id=1", ["id"]),   # destructive URL
    ])
    tester.run(ev, Scope.from_seed("http://test.local/"))
    assert calls == []


def test_respects_target_cap():
    calls = []
    probe = lambda url, params, *a, **k: calls.append(url) or []
    cfg = PipelineConfig(active_max_targets=2)
    tester = ActiveTester(config=cfg, xss=probe, sqli=probe, idor=probe, ssrf=probe, redirect=probe)
    ev = _Evidence(endpoints=[_ep(f"http://test.local/e{i}?id=1", ["id"]) for i in range(5)])
    tester.run(ev, Scope.from_seed("http://test.local/"))
    assert len(set(calls)) == 2  # only 2 endpoints probed


def test_non_destructive_form_is_tested():
    called = []
    probe = lambda url, fields, *a, **k: called.append((url, tuple(fields))) or []
    tester = ActiveTester(config=PipelineConfig(), xss=probe, sqli=probe,
                          idor=lambda *a, **k: [], ssrf=lambda *a, **k: [], redirect=lambda *a, **k: [])
    ev = _Evidence(forms=[
        {"action": "http://test.local/search", "method": "GET",
         "fields": [{"name": "q"}], "destructive": False},
        {"action": "http://test.local/delete", "method": "POST",
         "fields": [{"name": "id"}], "destructive": True},   # skipped
    ])
    tester.run(ev, Scope.from_seed("http://test.local/"))
    assert called and all("search" in url for url, _ in called)


def test_pipeline_active_stage_integration(collector):
    """Active findings flow through the backbone and dedup with the rest."""
    class FakeActive:
        def run(self, evidence, scope):
            return [{"type": "SQL Injection", "url": "http://test.local/api/v1/users?id",
                     "parameter": "id", "severity": "critical", "source": "active"}]

    cfg = PipelineConfig(active_testing=True)
    payload = Pipeline(config=cfg, collector=collector, groq=None, active=FakeActive()).run(
        "http://test.local/", write=False
    )
    assert "active" in payload["stages_run"]
    types = {f["type"] for f in payload["normalized_findings"]}
    assert "SQL Injection" in types
    assert any("active" in f.get("metadata", {}).get("sources", []) for f in payload["normalized_findings"])
