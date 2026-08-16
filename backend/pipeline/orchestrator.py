"""Pipeline orchestrator.

Chains every stage of the architecture end to end:

    URL -> Crawler -> Endpoint discovery -> JS extraction -> Unminify/unbundle
    -> Chunk/context generation -> RAG -> LLM analysis -> Finding normalization
    -> Deduplication -> Validation -> JSON/HTML report

Network fetching and the LLM are injected, so the whole pipeline is exercised in
tests against an in-memory site with no external calls.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional

from . import (
    chunking,
    crawler,
    dedup,
    endpoint_discovery,
    js_extraction,
    llm_analysis,
    normalization,
    reporting,
    unminify,
    validation,
)
from .config import PipelineConfig
from .models import Finding
from .rag import TfidfRetriever

logger = logging.getLogger("dsg.pipeline")


class Pipeline:
    def __init__(
        self,
        config: Optional[PipelineConfig] = None,
        fetch: Optional[crawler.Fetcher] = None,
        gemini=None,
    ) -> None:
        self.config = config or PipelineConfig()
        self.fetch = fetch or crawler.default_fetch(self.config.request_timeout)
        self.gemini = gemini
        self.stages: List[str] = []

    def _log(self, stage: str, message: str) -> None:
        self.stages.append(stage)
        logger.info("[%s] %s", stage, message)

    def _page_html(self, url: str) -> str:
        result = self.fetch(url)
        if result and result[0] == 200 and "html" in result[1].lower():
            return result[2]
        return ""

    def run(self, url: str, write: bool = True, reports_dir: str = "reports") -> Dict:
        cfg = self.config

        # 1. Crawler
        links = crawler.crawl(
            url,
            fetch=self.fetch,
            max_depth=cfg.max_depth,
            max_links=cfg.max_links,
            same_domain=cfg.same_domain,
        )
        self._log("crawler", f"{len(links)} URLs")

        pages: Dict[str, str] = {u: self._page_html(u) for u in links}
        status_code = 200 if pages.get(url) else 0

        # 3. JS extraction (needs pages) -> mine endpoints
        assets = js_extraction.extract_js_assets(pages, fetch=self.fetch)
        js_endpoints = js_extraction.mine_endpoints(assets)
        self._log("js_extraction", f"{len(assets)} assets, {len(js_endpoints)} endpoints")

        # 2. Endpoint discovery
        endpoints = endpoint_discovery.discover_endpoints(
            links, js_endpoints=js_endpoints, base_url=url
        )
        self._log("endpoint_discovery", f"{len(endpoints)} endpoints")

        # 4. Unminify / unbundle
        assets = unminify.process(assets)
        self._log("unminify", f"{len(assets)} processed assets")

        # 5. Chunk / context generation
        chunks = chunking.build_chunks(
            assets, pages, endpoints, size=cfg.chunk_size, overlap=cfg.chunk_overlap
        )
        self._log("chunking", f"{len(chunks)} chunks")

        # 6. RAG
        retriever = TfidfRetriever().fit(chunks)
        self._log("rag", "index built")

        # 7. LLM analysis
        raw = llm_analysis.analyze(
            retriever,
            gemini=self.gemini if cfg.use_llm else None,
            top_k=cfg.retrieval_top_k,
        )
        self._log("llm_analysis", f"{len(raw)} raw findings")

        # 8. Normalisation
        normalized: List[Finding] = normalization.normalize(raw)
        self._log("normalization", f"{len(normalized)} normalized")

        # 9. Deduplication
        deduped = dedup.deduplicate(normalized)
        self._log("deduplication", f"{len(deduped)} unique")

        # 10. Validation
        valid, rejected = validation.validate(
            deduped, drop_low_confidence=cfg.drop_low_confidence
        )
        self._log("validation", f"{len(valid)} valid, {len(rejected)} rejected")

        # 11. JSON / HTML report
        discovery = {
            "links": links,
            "js_endpoints": js_endpoints,
            "directories": [],
            "subdomains": [],
        }
        payload = reporting.build_payload(
            url, status_code, valid, discovery, rejected=rejected
        )
        if write:
            payload["reports"] = reporting.write_reports(payload, reports_dir)
        self._log("reporting", "done")
        payload["stages_run"] = list(self.stages)
        return payload


def run_pipeline(url: str, config: Optional[PipelineConfig] = None, gemini=None) -> Dict:
    """Convenience entry point mirroring the legacy ``scan_url`` signature."""
    return Pipeline(config=config or PipelineConfig.from_env(), gemini=gemini).run(url)
