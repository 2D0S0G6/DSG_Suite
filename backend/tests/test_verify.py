"""Autonomous browser verification (offline, injected probe)."""

from pipeline import PipelineConfig
from pipeline.models import Finding
from pipeline.orchestrator import Pipeline
from pipeline.scope import Scope
from pipeline.verify import verify_findings


def _finding(type_="DOM XSS", url="http://test.local/", parameter=""):
    f = Finding(type=type_, url=url, parameter=parameter, confidence="medium")
    f.compute_fingerprint()
    return f


def test_confirms_when_canary_executes():
    scope = Scope.from_seed("http://test.local/")
    calls = []

    def probe(target, nonce):
        calls.append(target)
        return True  # canary "executed"

    findings, notes = verify_findings([_finding()], scope, PipelineConfig(), probe=probe)
    f = findings[0]
    assert f.metadata["verified"] is True
    assert f.confidence == "high"
    assert f.metadata["verification"]["poc"]
    assert calls and notes[0]["verified"] is True


def test_unconfirmed_when_canary_silent():
    scope = Scope.from_seed("http://test.local/")
    findings, notes = verify_findings([_finding()], scope, PipelineConfig(), probe=lambda t, n: False)
    f = findings[0]
    assert f.metadata["verified"] is False
    assert f.confidence == "medium"  # not promoted
    assert "verification" not in f.metadata


def test_non_verifiable_findings_untouched():
    scope = Scope.from_seed("http://test.local/")
    findings, notes = verify_findings(
        [_finding(type_="Missing Security Headers")], scope, PipelineConfig(), probe=lambda t, n: True
    )
    assert "verified" not in findings[0].metadata
    assert notes == [{"note": "no browser-verifiable findings"}]


def test_out_of_scope_target_is_not_probed():
    scope = Scope.from_seed("http://test.local/")
    calls = []
    findings, _ = verify_findings(
        [_finding(url="http://evil.example.com/x")], scope, PipelineConfig(),
        probe=lambda t, n: calls.append(t) or True,
    )
    assert calls == []                       # scope gate blocked the probe
    assert findings[0].metadata["verified"] is False


def test_probe_exception_is_safe():
    scope = Scope.from_seed("http://test.local/")

    def boom(target, nonce):
        raise RuntimeError("browser crashed")

    findings, _ = verify_findings([_finding()], scope, PipelineConfig(), probe=boom)
    assert findings[0].metadata["verified"] is False  # degraded, not crashed


def test_pipeline_runs_verification_stage(collector):
    cfg = PipelineConfig(verify_findings=True)
    payload = Pipeline(config=cfg, collector=collector, groq=None, probe=lambda t, n: True).run(
        "http://test.local/", write=False
    )
    assert "verify" in payload["stages_run"]
    assert payload.get("verification")
    assert any(f.get("metadata", {}).get("verified") for f in payload["normalized_findings"])
