from pipeline import PipelineConfig
from pipeline.orchestrator import Pipeline


def test_full_pipeline_offline(fetch, tmp_path):
    cfg = PipelineConfig(max_links=10, chunk_size=400, chunk_overlap=50)
    pipe = Pipeline(config=cfg, fetch=fetch, gemini=None)
    result = pipe.run("http://test.local/", write=True, reports_dir=str(tmp_path))

    # Every architecture stage ran, in order.
    assert result["stages_run"][:6] == [
        "crawler",
        "js_extraction",
        "endpoint_discovery",
        "unminify",
        "chunking",
        "rag",
    ]

    # Findings were produced by the offline heuristic path.
    types = {f["type"] for f in result["normalized_findings"]}
    assert "DOM XSS" in types
    assert "Hardcoded Secret" in types

    # Discovery metadata is populated.
    assert "http://test.local/profile?id=1" in result["links_found"]
    assert any("/api/v1/users" in e for e in result["js_endpoints"])

    # Summary is coherent.
    assert result["summary"]["total"] == len(result["normalized_findings"])


def test_pipeline_uses_gemini_when_available(fetch, fake_gemini, tmp_path):
    pipe = Pipeline(config=PipelineConfig(), fetch=fetch, gemini=fake_gemini)
    result = pipe.run("http://test.local/", write=False)
    sources = set()
    for f in result["normalized_findings"]:
        sources.update(f["metadata"].get("sources", [f["source"]]))
    assert "gemini-rag" in sources


def test_pipeline_no_write(fetch):
    result = Pipeline(fetch=fetch, gemini=None).run("http://test.local/", write=False)
    assert "reports" not in result
