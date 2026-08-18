"""Read-only tools exposed to the agent + the dispatcher that runs them.

The agent can only *read* the corpus that deterministic collection already
produced.  There are deliberately no browser-control or request-sending tools —
that is the architectural half of the boundary: the agent cannot touch the
target, only reason about the evidence.
"""

from __future__ import annotations

import json
from typing import Dict, List

from ..evidence import Evidence
from ..rag import TfidfRetriever

# OpenAI/Groq-compatible tool schemas.
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "rag_search",
            "description": "Semantic search over collected client-side code, DOM and evidence. "
            "Use to find sinks, endpoints, secrets, auth logic, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What to look for"},
                    "top_k": {"type": "integer", "description": "How many chunks (1-8)", "default": 5},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_evidence",
            "description": "Return a shaped evidence inventory by name: one of "
            "endpoints, forms, dom_sinks, network_map, storage, security_headers, secrets, pages.",
            "parameters": {
                "type": "object",
                "properties": {"form": {"type": "string"}},
                "required": ["form"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_source",
            "description": "Return the (redacted) collected content for a given source URL "
            "(a page or a JS file). Use list_sources first to see what exists.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_sources",
            "description": "List the source URLs available in the collected corpus.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_finding",
            "description": "Record ONE confirmed security finding, grounded in the evidence you read.",
            "parameters": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "description": "Vulnerability class, e.g. 'DOM XSS'"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "url": {"type": "string"},
                    "parameter": {"type": "string"},
                    "evidence": {"type": "string", "description": "The concrete evidence snippet/location"},
                    "description": {"type": "string"},
                    "remediation": {"type": "string"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["type", "severity", "description"],
            },
        },
    },
]


class ToolContext:
    """Executes tool calls against the collected corpus and records findings."""

    def __init__(self, retriever: TfidfRetriever, evidence: Evidence) -> None:
        self.retriever = retriever
        self.evidence = evidence
        self.findings: List[Dict] = []
        self.trace: List[Dict] = []
        self._tool_calls = 0

    @property
    def tool_calls(self) -> int:
        return self._tool_calls

    def execute(self, name: str, args: Dict) -> str:
        self._tool_calls += 1
        try:
            observation = self._dispatch(name, args)
        except Exception as exc:  # never let a bad tool call kill the loop
            observation = f"error: {exc}"
        self.trace.append({"tool": name, "args": args, "observation_preview": observation[:200]})
        return observation

    def _dispatch(self, name: str, args: Dict) -> str:
        if name == "rag_search":
            top_k = max(1, min(int(args.get("top_k", 5) or 5), 8))
            chunks = self.retriever.retrieve(args.get("query", ""), top_k=top_k)
            if not chunks:
                return "No matching context."
            return "\n---\n".join(f"[{c.kind}] {c.source}\n{c.content[:700]}" for c in chunks)

        if name == "get_evidence":
            form = (args.get("form") or "").strip()
            if form not in self.evidence.form_names():
                return f"Unknown form '{form}'. Available: {', '.join(self.evidence.form_names())}."
            return json.dumps(getattr(self.evidence, form), indent=2)[:3000]

        if name == "list_sources":
            sources = sorted({c.source for c in self.retriever.chunks})
            return "\n".join(sources) or "No sources."

        if name == "read_source":
            url = (args.get("url") or "").strip()
            matched = [c for c in self.retriever.chunks if c.source == url or url in c.source]
            if not matched:
                return f"No content for '{url}'."
            return "\n".join(c.content for c in matched)[:3500]

        if name == "report_finding":
            finding = {
                "type": args.get("type", "Unknown"),
                "severity": args.get("severity", "medium"),
                "url": args.get("url", ""),
                "parameter": args.get("parameter", ""),
                "evidence": args.get("evidence", ""),
                "description": args.get("description", ""),
                "remediation": args.get("remediation", ""),
                "confidence": args.get("confidence", "medium"),
                "source": "agentic",
            }
            self.findings.append(finding)
            return f"Recorded finding: {finding['type']} ({finding['severity']})."

        return f"Unknown tool '{name}'."
