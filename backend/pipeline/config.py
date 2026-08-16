"""Tunable knobs for the pipeline, all overridable via environment variables so
CI and local runs can dial coverage up or down without code changes."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class PipelineConfig:
    # Crawler
    max_depth: int = 2
    max_links: int = 50
    same_domain: bool = True
    request_timeout: int = 10

    # Chunking
    chunk_size: int = 1200      # characters per chunk
    chunk_overlap: int = 150

    # RAG
    retrieval_top_k: int = 6

    # LLM
    use_llm: bool = True        # falls back to offline heuristics if unavailable

    # Validation
    drop_low_confidence: bool = False

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        return cls(
            max_depth=_int("DSG_MAX_DEPTH", 2),
            max_links=_int("DSG_MAX_LINKS", 50),
            same_domain=os.getenv("DSG_SAME_DOMAIN", "1") != "0",
            request_timeout=_int("DSG_TIMEOUT", 10),
            chunk_size=_int("DSG_CHUNK_SIZE", 1200),
            chunk_overlap=_int("DSG_CHUNK_OVERLAP", 150),
            retrieval_top_k=_int("DSG_TOP_K", 6),
            use_llm=os.getenv("DSG_USE_LLM", "1") != "0",
            drop_low_confidence=os.getenv("DSG_DROP_LOW_CONFIDENCE", "0") == "1",
        )
