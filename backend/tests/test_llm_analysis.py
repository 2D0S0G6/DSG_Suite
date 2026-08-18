from pipeline import llm_analysis
from pipeline.models import Chunk
from pipeline.rag import TfidfRetriever


def _retriever():
    chunks = [
        Chunk(id="1", source="http://x/app.js", kind="js",
              content="el.innerHTML = location.hash; // sink"),
        Chunk(id="2", source="http://x/app.js", kind="js",
              content="var api_key = 'SUPERSECRETKEY123456';"),
        Chunk(id="3", source="http://x/app.js", kind="js",
              content="fetch('http://x/api/v1/users?id=42');"),
    ]
    return TfidfRetriever().fit(chunks)


def test_heuristics_detect_dom_xss_and_secret():
    raw = llm_analysis.analyze(_retriever(), groq=None)
    types = {r["type"] for r in raw}
    assert "DOM XSS" in types
    assert "Hardcoded Secret" in types


def test_heuristics_detect_insecure_transport_and_idor():
    raw = llm_analysis.analyze(_retriever(), groq=None)
    types = {r["type"] for r in raw}
    assert "Insecure Transport" in types
    assert "Potential IDOR" in types


def test_groq_path_used_when_available(fake_groq):
    raw = llm_analysis.analyze(_retriever(), groq=fake_groq)
    assert any(r["source"] == "groq-rag" for r in raw)


def test_unavailable_groq_falls_back_to_heuristics():
    class Down:
        def is_available(self):
            return False

    raw = llm_analysis.analyze(_retriever(), groq=Down())
    assert raw and all(r["source"] == "heuristic-rag" for r in raw)
