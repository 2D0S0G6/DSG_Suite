from pipeline import PipelineConfig
from pipeline.orchestrator import Pipeline


def test_full_pipeline_offline(fetch, tmp_path):
    cfg = PipelineConfig(max_pages=10, chunk_size=400, chunk_overlap=50)
    pipe = Pipeline(config=cfg, fetch=fetch, groq=None)
    result = pipe.run("http://test.local/", write=True, reports_dir=str(tmp_path))

    # Every stage ran, in order (deterministic collect/shape/rag -> analyze -> backbone).
    assert result["stages_run"][:6] == [
        "scope",
        "collect",
        "evidence",
        "rag",
        "analyze",
        "backbone",
    ]

    # Findings were produced by the deterministic baseline + offline heuristics.
    types = {f["type"] for f in result["normalized_findings"]}
    assert "DOM XSS" in types
    assert "Hardcoded Secret" in types

    # Discovery metadata is populated from the shaped evidence.
    assert "http://test.local/profile?id=1" in result["links_found"]
    assert any("/api/v1/users" in e for e in result["js_endpoints"])

    # Summary is coherent.
    assert result["summary"]["total"] == len(result["normalized_findings"])

    # The offline path used the requests collector, and a dashboard was written.
    assert result["collector"] == "RequestsCollector"
    assert result["reports"]["dashboard"].endswith("dashboard.html")


def test_pipeline_uses_agent_when_available(fetch, fake_agent, tmp_path):
    pipe = Pipeline(config=PipelineConfig(), fetch=fetch, groq=fake_agent)
    result = pipe.run("http://test.local/", write=False)
    sources = set()
    for f in result["normalized_findings"]:
        sources.update(f["metadata"].get("sources", [f["source"]]))
    assert "agentic" in sources  # the agent reported at least one finding


def test_pipeline_no_write(fetch):
    result = Pipeline(fetch=fetch, groq=None).run("http://test.local/", write=False)
    assert "reports" not in result
