"""Agentic analysis layer.

A bounded Groq tool-calling agent that reasons over the deterministically
collected, shaped and redacted corpus (RAG index + evidence forms) using
**read-only** retrieval tools, and emits findings through the same
normalize -> dedup -> validate -> report backbone as every other engine.

The agent never drives the browser and never acts on the target — it only reads
the evidence gathered upstream.
"""

from __future__ import annotations

from .loop import AgenticAnalyzer, analyze

__all__ = ["AgenticAnalyzer", "analyze"]
