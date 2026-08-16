"""DSG Suite analysis pipeline.

A staged, dependency-injected re-implementation of the scanner architecture:

    URL -> Crawler -> Endpoint discovery -> JS extraction -> Unminify/unbundle
    -> Chunk/context generation -> RAG -> LLM analysis -> Finding normalization
    -> Deduplication -> Validation -> JSON/HTML report

Each stage lives in its own module and can be tested in isolation.  The
:class:`~pipeline.orchestrator.Pipeline` wires them together.
"""

from __future__ import annotations

from .config import PipelineConfig
from .models import Chunk, Endpoint, Finding, JSAsset
from .orchestrator import Pipeline, run_pipeline

__all__ = [
    "PipelineConfig",
    "Pipeline",
    "run_pipeline",
    "Finding",
    "Chunk",
    "Endpoint",
    "JSAsset",
]
