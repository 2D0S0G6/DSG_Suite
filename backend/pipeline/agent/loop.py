"""The bounded agentic reasoning loop.

Runs a Groq tool-calling agent over the collected corpus.  Every iteration the
model may call read-only tools (search, read evidence/sources) and ultimately
``report_finding`` for each vulnerability it can ground in the evidence.

The loop is the enforcement point for the **resource-budget** boundary: it stops
at ``max_agent_steps`` model turns, ``max_tool_calls`` tool invocations, or a
wall-clock deadline — whichever comes first.  With no usable Groq client it
degrades to the deterministic heuristic detectors so the engine still produces
findings offline.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, List, Tuple

from .. import llm_analysis
from ..evidence import Evidence
from ..rag import TfidfRetriever
from .tools import TOOL_SCHEMAS, ToolContext

logger = logging.getLogger("dsg.agent")

SYSTEM_PROMPT = (
    "You are an autonomous web application security analyst. You are given a corpus of "
    "CLIENT-SIDE evidence already collected from a target (rendered DOM, JavaScript, network "
    "map, storage, forms and shaped inventories). You CANNOT touch the target — only reason "
    "over the evidence using the read-only tools.\n\n"
    "Method:\n"
    "1. Call get_evidence on the inventories (dom_sinks, endpoints, forms, network_map, "
    "storage, security_headers, secrets) to orient.\n"
    "2. Use rag_search / read_source to confirm suspicious code paths.\n"
    "3. Call report_finding for an issue AS SOON AS you have evidence for it — do not wait "
    "until the end or over-explore. Prefer precision over volume; never invent findings you "
    "cannot cite.\n"
    "4. When you have reported everything you can support, reply with the single word DONE.\n\n"
    "Focus areas: DOM/stored XSS sinks fed by tainted sources, missing CSRF tokens on "
    "state-changing forms, hardcoded secrets, insecure transport / mixed content, IDOR-shaped "
    "endpoints, weak cookie flags, missing security headers, over-permissive CORS."
)


def _assistant_msg_to_dict(message) -> Dict:
    """Serialise a Groq assistant message (possibly with tool_calls) to a dict."""
    tool_calls = []
    for tc in getattr(message, "tool_calls", None) or []:
        tool_calls.append(
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments},
            }
        )
    msg: Dict = {"role": "assistant", "content": getattr(message, "content", "") or ""}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return msg


class AgenticAnalyzer:
    def __init__(self, groq=None, config=None) -> None:
        self.groq = groq
        self.config = config

    def _budget(self, name: str, default):
        return getattr(self.config, name, default) if self.config else default

    def analyze(self, retriever: TfidfRetriever, evidence: Evidence) -> Tuple[List[Dict], List[Dict]]:
        """Return (raw_findings, agent_trace)."""
        use_agent = (
            bool(self.groq)
            and getattr(self.groq, "is_available", lambda: False)()
            and hasattr(self.groq, "chat_with_tools")
        )
        if not use_agent:
            logger.info("No usable Groq client; falling back to heuristic detectors.")
            raw = llm_analysis.analyze(retriever, groq=None, top_k=self._budget("retrieval_top_k", 6))
            return raw, [{"tool": "heuristic_fallback", "args": {}, "observation_preview": f"{len(raw)} findings"}]

        max_steps = self._budget("max_agent_steps", 6)
        max_tool_calls = self._budget("max_tool_calls", 20)
        deadline = time.time() + self._budget("agent_time_budget", 120)

        ctx = ToolContext(retriever, evidence)
        messages: List[Dict] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Begin the assessment. Available evidence forms: "
                + ", ".join(evidence.form_names())
                + ". Investigate, then report findings and reply DONE.",
            },
        ]

        for step in range(max_steps):
            if ctx.tool_calls >= max_tool_calls or time.time() > deadline:
                logger.info("Budget reached (tool_calls=%s, step=%s).", ctx.tool_calls, step)
                break

            message = self.groq.chat_with_tools(messages, tools=TOOL_SCHEMAS, tool_choice="auto")
            if message is None:
                logger.info("Groq call failed mid-loop; stopping with %d findings.", len(ctx.findings))
                break

            tool_calls = getattr(message, "tool_calls", None) or []
            messages.append(_assistant_msg_to_dict(message))

            if not tool_calls:
                break  # model produced a final (likely DONE) message

            for tc in tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except Exception:
                    args = {}
                observation = ctx.execute(tc.function.name, args)
                messages.append(
                    {"role": "tool", "tool_call_id": tc.id, "content": observation[:1500]}
                )
                if ctx.tool_calls >= max_tool_calls:
                    break

        # Safety net: if the agent surfaced nothing at all, back it with heuristics
        # so a degraded model turn never yields an empty report.
        if not ctx.findings:
            raw = llm_analysis.analyze(retriever, groq=None, top_k=self._budget("retrieval_top_k", 6))
            ctx.findings.extend(raw)
            ctx.trace.append({"tool": "heuristic_safety_net", "args": {}, "observation_preview": f"{len(raw)} findings"})

        return ctx.findings, ctx.trace


def analyze(retriever: TfidfRetriever, evidence: Evidence, groq=None, config=None):
    return AgenticAnalyzer(groq=groq, config=config).analyze(retriever, evidence)
