"""Pipeline orchestrator — one pipeline, deterministic stages + a pluggable analyzer.

    URL
      -> Scope            (boundary: host allowlist, read-only)
      -> Collect          (deterministic: Playwright browser | requests fallback)
      -> Evidence shaping (deterministic: raw captures -> redacted typed "forms")
      -> Chunk + RAG      (deterministic: unminify JS, redact, index)
      -> Analyze          (the one AI stage: bounded Groq agent | heuristics)
      -> normalize -> dedup -> validate -> report (+ dashboard)

Everything left of *Analyze* is deterministic data retrieval and processing; the
agent is simply the stage that reasons over the shaped corpus.  The browser and
the agent are **config toggles** (``prefer_browser`` / ``use_llm``), not separate
orchestrators — so the same class serves the lightweight ``/scan/pipeline`` preset
(requests + heuristics) and the full ``/scan/agentic`` preset (browser + agent).

Collection and the LLM are injected (``collector`` / ``fetch`` / ``groq``), so the
whole pipeline runs offline and deterministically in tests.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from . import (
    chunking,
    dedup,
    evidence as evidence_mod,
    normalization,
    reporting,
    unminify,
    validation,
)
from .agent import loop as agent_loop
from .collectors.base import RequestsCollector, default_collector
from .config import PipelineConfig
from .models import Finding, JSAsset
from .rag import TfidfRetriever
from .redaction import redact
from .scope import Scope

logger = logging.getLogger("dsg.pipeline")


class Pipeline:
    def __init__(
        self,
        config: Optional[PipelineConfig] = None,
        collector=None,
        groq=None,
        fetch=None,
        probe=None,
        active=None,
    ) -> None:
        self.config = config or PipelineConfig()
        # Collection backend precedence: explicit collector > injected fetch
        # (offline/tests) > auto-selected default (browser when preferred+available).
        if collector is not None:
            self.collector = collector
        elif fetch is not None:
            self.collector = RequestsCollector(fetch=fetch)
        else:
            self.collector = default_collector(self.config.prefer_browser)
        self.groq = groq
        self.probe = probe  # injected browser verification probe (tests / custom)
        self.active = active  # injected active-testing runner (tests / custom)
        self.stages: List[str] = []

    def _log(self, stage: str, message: str) -> None:
        self.stages.append(stage)
        logger.info("[%s] %s", stage, message)

    def _build_chunks(self, captures, ev) -> List:
        """Redacted DOM/JS chunks (JS beautified+unbundled) + evidence chunks."""
        cfg = self.config
        redact_fn = redact if cfg.redact else (lambda s: s)
        chunks: List = []

        # Rendered DOM per page.
        for cap in captures:
            if cap.dom:
                chunks += chunking.chunk_html(
                    {cap.url: redact_fn(cap.dom)}, cfg.chunk_size, cfg.chunk_overlap
                )

        # JS: deterministic unminify/unbundle -> redact -> chunk.
        assets = [s for cap in captures for s in cap.scripts]
        for asset in unminify.process(assets):
            red = JSAsset(url=asset.url, content=redact_fn(asset.content), inline=asset.inline)
            chunks += chunking.chunk_js([red], cfg.chunk_size, cfg.chunk_overlap)

        # Shaped evidence forms, retrievable alongside the code.
        chunks += evidence_mod.to_chunks(ev)
        return chunks

    def run(self, url: str, write: bool = True, reports_dir: str = "reports") -> Dict:
        cfg = self.config

        # 1. Boundary: scope from the seed URL.
        scope = Scope.from_seed(
            url,
            allow_subdomains=cfg.allow_subdomains,
            max_pages=cfg.max_pages,
            read_only=cfg.read_only,
        )
        self._log("scope", f"host(s)={scope.hosts} read_only={scope.read_only}")

        # 2. Deterministic collection (in-scope, read-only).
        captures = self.collector.collect(scope, cfg)
        collector_name = type(self.collector).__name__
        self._log("collect", f"{len(captures)} pages via {collector_name}")
        status_code = next((c.status for c in captures if c.url == url), 0) or (
            captures[0].status if captures else 0
        )

        # 3. Deterministic evidence shaping (redacted typed forms).
        ev = evidence_mod.shape(captures, scope, cfg)
        self._log(
            "evidence",
            f"{len(ev.endpoints)} endpoints, {len(ev.forms)} forms, "
            f"{len(ev.dom_sinks)} sinks, {len(ev.secrets)} secrets",
        )

        # 4. Chunk + RAG over the redacted corpus + evidence.
        chunks = self._build_chunks(captures, ev)
        retriever = TfidfRetriever().fit(chunks)
        self._log("rag", f"{len(chunks)} chunks indexed")

        # 5. Analysis — deterministic baseline facts + the AI stage
        #    (bounded agent when a key is present, else heuristic detectors).
        baseline = evidence_mod.baseline_findings(ev)
        agent_raw, trace = agent_loop.analyze(
            retriever, ev, groq=self.groq if cfg.use_llm else None, config=cfg
        )
        raw = baseline + agent_raw
        self._log("analyze", f"{len(baseline)} baseline + {len(agent_raw)} agent, {len(trace)} trace steps")

        # 5c. Active testing (opt-in): send real payloads to in-scope targets.
        if cfg.active_testing:
            from .active import ActiveTester

            tester = self.active or ActiveTester(config=cfg)
            active_raw = tester.run(ev, scope)
            raw += active_raw
            self._log("active", f"{len(active_raw)} active findings")

        # 6. Shared backbone: normalize -> dedup (corroboration) -> validate.
        normalized: List[Finding] = normalization.normalize(raw)
        deduped = dedup.deduplicate(normalized)
        valid, rejected = validation.validate(deduped, drop_low_confidence=cfg.drop_low_confidence)
        self._log("backbone", f"{len(valid)} valid, {len(rejected)} rejected")

        # 6b. Autonomous browser verification of candidate bugs (opt-in).
        verification: List[dict] = []
        if cfg.verify_findings:
            from . import verify

            valid, verification = verify.verify_findings(valid, scope, cfg, probe=self.probe)
            confirmed = sum(1 for n in verification if n.get("verified"))
            self._log("verify", f"{confirmed} confirmed in-browser")
            trace.append(
                {"tool": "browser_verify", "args": {}, "observation_preview": f"{confirmed} confirmed"}
            )

        # 7. Report (+ evidence, network map, agent trace, dashboard).
        discovery = {
            "links": sorted({l for c in captures for l in c.links}),
            "js_endpoints": [e["url"] for e in ev.endpoints if e.get("source") == "javascript"],
            "directories": [],
            "subdomains": [],
        }
        payload = reporting.build_payload(
            url,
            status_code,
            valid,
            discovery,
            rejected=rejected,
            evidence=ev.to_dict(),
            agent_trace=trace,
            network_map=ev.network_map,
        )
        payload["collector"] = collector_name
        if verification:
            payload["verification"] = verification
        if write:
            payload["reports"] = reporting.write_reports(payload, reports_dir)
            from .dashboard import write_dashboard

            payload["reports"]["dashboard"] = write_dashboard(payload, reports_dir)
        self._log("report", "done")
        payload["stages_run"] = list(self.stages)
        return payload


def run_pipeline(
    url: str, config: Optional[PipelineConfig] = None, groq=None, fetch=None
) -> Dict:
    """Lightweight preset: requests collection + agent-or-heuristic analysis."""
    return Pipeline(
        config=config or PipelineConfig.from_env(), groq=groq, fetch=fetch
    ).run(url)


def run_agentic(url: str, config: Optional[PipelineConfig] = None, groq=None) -> Dict:
    """Full preset: browser + agent + active testing + browser verification."""
    cfg = config or PipelineConfig.from_env()
    cfg.prefer_browser = True
    cfg.verify_findings = True
    cfg.active_testing = True
    return Pipeline(config=cfg, groq=groq).run(url)
