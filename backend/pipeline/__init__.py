"""DSG Suite analysis pipeline.

One dependency-injected pipeline whose deterministic stages retrieve and shape
the client-side data, and whose single AI stage reasons over it:

    URL -> Scope -> Collect (browser | requests) -> Evidence shaping (redacted)
    -> Chunk + RAG -> Analyze (bounded Groq agent | heuristics)
    -> Normalize -> Deduplicate -> Validate -> report (+ dashboard)

Browser-vs-requests collection and agent-vs-heuristic analysis are config
toggles (``prefer_browser`` / ``use_llm``), so :class:`~pipeline.orchestrator.Pipeline`
serves both the lightweight ``run_pipeline`` and full-browser ``run_agentic``
presets.  Each stage lives in its own module and can be tested in isolation.
"""

from __future__ import annotations

from .config import PipelineConfig
from .models import Chunk, Endpoint, Finding, JSAsset
from .orchestrator import Pipeline, run_agentic, run_pipeline

__all__ = [
    "PipelineConfig",
    "Pipeline",
    "run_pipeline",
    "run_agentic",
    "Finding",
    "Chunk",
    "Endpoint",
    "JSAsset",
]
