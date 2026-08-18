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

    # --- Client-side collection: boundary & budgets -----------------------------
    prefer_browser: bool = False  # base preset = requests; run_agentic flips this on
    read_only: bool = True        # never fire state-changing requests/submits
    allow_subdomains: bool = False
    max_pages: int = 40           # scope cap on pages collected
    nav_timeout: int = 15         # per-page browser navigation timeout (seconds)
    redact: bool = True           # strip secrets before anything reaches the model
    max_agent_steps: int = 8      # model turns in the agent loop
    max_tool_calls: int = 20      # total tool invocations per scan
    agent_time_budget: int = 120  # wall-clock cap for the agent loop (seconds)
    verify_findings: bool = False  # actively confirm XSS-class findings in a browser
    active_testing: bool = False   # send real payloads: reflected XSS/SQLi/IDOR/SSRF/redirect
    active_max_targets: int = 15   # cap on endpoints/forms actively probed

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
            prefer_browser=os.getenv("DSG_PREFER_BROWSER", "0") == "1",
            read_only=os.getenv("DSG_READ_ONLY", "1") != "0",
            allow_subdomains=os.getenv("DSG_ALLOW_SUBDOMAINS", "0") == "1",
            max_pages=_int("DSG_MAX_PAGES", 40),
            nav_timeout=_int("DSG_NAV_TIMEOUT", 15),
            redact=os.getenv("DSG_REDACT", "1") != "0",
            max_agent_steps=_int("DSG_MAX_AGENT_STEPS", 8),
            max_tool_calls=_int("DSG_MAX_TOOL_CALLS", 20),
            agent_time_budget=_int("DSG_AGENT_TIME_BUDGET", 120),
            verify_findings=os.getenv("DSG_VERIFY", "0") == "1",
            active_testing=os.getenv("DSG_ACTIVE", "0") == "1",
            active_max_targets=_int("DSG_ACTIVE_MAX", 15),
        )
