"""End-to-end agentic engine (offline: injected collector + fake agent)."""

from pipeline import PipelineConfig
from pipeline.orchestrator import Pipeline
from pipeline.dashboard import render_dashboard


def test_agentic_pipeline_end_to_end(collector, fake_agent):
    payload = Pipeline(config=PipelineConfig(), collector=collector, groq=fake_agent).run(
        "http://test.local/", write=False
    )
    assert payload["stages_run"] == ["scope", "collect", "evidence", "rag", "analyze", "backbone", "report"]
    assert payload["summary"]["total"] > 0
    assert payload.get("evidence") and payload.get("agent_trace")
    # deterministic baseline + agent findings both present
    sources = {s for f in payload["normalized_findings"] for s in f.get("metadata", {}).get("sources", [])}
    assert "evidence" in sources


def test_agentic_pipeline_offline_without_agent(collector):
    payload = Pipeline(config=PipelineConfig(), collector=collector, groq=None).run(
        "http://test.local/", write=False
    )
    types = {f["type"] for f in payload["normalized_findings"]}
    assert "Hardcoded Secret" in types  # from deterministic evidence baseline


def test_agentic_report_never_leaks_secret(collector, fake_agent):
    import json

    payload = Pipeline(config=PipelineConfig(), collector=collector, groq=fake_agent).run(
        "http://test.local/", write=False
    )
    assert "SUPERSECRETKEY123456" not in json.dumps(payload)
    assert "SUPERSECRETKEY123456" not in render_dashboard(payload)


def test_read_only_collection_issues_no_writes(collector):
    """The offline collector only performs GETs — nothing state-changing."""
    caps = collector.collect(
        __import__("pipeline.scope", fromlist=["Scope"]).Scope.from_seed("http://test.local/")
    )
    for cap in caps:
        assert all(n.method.upper() == "GET" for n in cap.network)
