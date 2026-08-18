"""Agent loop: tool dispatch, budgets, and graceful fallback."""

from pipeline import chunking, evidence as evidence_mod
from pipeline.agent.loop import AgenticAnalyzer
from pipeline.agent.tools import ToolContext
from pipeline.collectors.base import RequestsCollector
from pipeline.config import PipelineConfig
from pipeline.rag import TfidfRetriever
from pipeline.scope import Scope
from tests.conftest import FakeGroqAgent, tool_call, _FakeMessage


def _corpus(fetch):
    """Build a retriever like the real pipeline: DOM + JS + evidence chunks."""
    scope = Scope.from_seed("http://test.local/")
    caps = RequestsCollector(fetch=fetch).collect(scope)
    ev = evidence_mod.shape(caps, scope)
    chunks = []
    for cap in caps:
        if cap.dom:
            chunks += chunking.chunk_html({cap.url: cap.dom})
        for asset in cap.scripts:
            chunks += chunking.chunk_js([asset])
    chunks += evidence_mod.to_chunks(ev)
    retriever = TfidfRetriever().fit(chunks)
    return retriever, ev


def test_agent_records_findings_via_tool(fetch, fake_agent):
    retriever, ev = _corpus(fetch)
    findings, trace = AgenticAnalyzer(groq=fake_agent, config=PipelineConfig()).analyze(retriever, ev)
    assert any(f["type"] == "DOM XSS" and f["source"] == "agentic" for f in findings)
    tools_used = [t["tool"] for t in trace]
    assert "get_evidence" in tools_used and "report_finding" in tools_used


def test_tool_context_reads_evidence_and_rejects_unknown(fetch):
    retriever, ev = _corpus(fetch)
    ctx = ToolContext(retriever, ev)
    assert "dom_sinks" not in ctx.execute("get_evidence", {"form": "does_not_exist"}) or "Unknown" in ctx.execute(
        "get_evidence", {"form": "does_not_exist"}
    )
    out = ctx.execute("get_evidence", {"form": "secrets"})
    assert "SUPERSECRETKEY123456" not in out  # corpus is redacted


def test_tool_call_budget_stops_the_loop(fetch):
    retriever, ev = _corpus(fetch)
    # A script that would keep calling tools forever.
    script = [tool_call(f"c{i}", "get_evidence", form="endpoints") for i in range(10)]
    agent = FakeGroqAgent(script=script)
    cfg = PipelineConfig(max_tool_calls=1, max_agent_steps=10)
    _, trace = AgenticAnalyzer(groq=agent, config=cfg).analyze(retriever, ev)
    real_calls = [t for t in trace if t["tool"] not in ("heuristic_safety_net", "heuristic_fallback")]
    assert len(real_calls) == 1  # budget capped tool execution at 1


def test_empty_agent_triggers_safety_net(fetch):
    retriever, ev = _corpus(fetch)
    agent = FakeGroqAgent(script=[_FakeMessage(content="DONE")])  # reports nothing
    findings, trace = AgenticAnalyzer(groq=agent, config=PipelineConfig()).analyze(retriever, ev)
    assert any(t["tool"] == "heuristic_safety_net" for t in trace)
    assert findings  # not left empty


def test_no_groq_falls_back_to_heuristics(fetch):
    retriever, ev = _corpus(fetch)
    findings, trace = AgenticAnalyzer(groq=None, config=PipelineConfig()).analyze(retriever, ev)
    assert trace and trace[0]["tool"] == "heuristic_fallback"
    assert isinstance(findings, list)
