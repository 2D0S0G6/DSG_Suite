"""Combined scan — unify the two engines through one funnel.

The staged **pipeline** engine is strong at *analysis* (crawl, JS
extraction/unminify, RAG retrieval, LLM reasoning) but its detectors are shallow
(a handful of passive regex indicators). The **legacy** engine
(``scanner.scan_url``) is the opposite: deep *active* detectors that send
payloads and confirm exploitability (context-aware XSS, four-family SQLi,
multi-role authorization, active IDOR mutation, timing/boolean oracles) but no
finding hygiene.

This module is the tactical adapter that gets the best of both: it runs each
engine, then pushes **all** of their findings through the pipeline's shared
backbone —

    normalize  ->  dedup (cross-engine corroboration)  ->  validate  ->  report

so the two engines converge on one canonical :class:`Finding` stream, one
deduplicated report, and one confidence model. When a regex-confirmed finding and
an LLM-reasoned finding land on the same fingerprint, ``dedup`` merges them and
raises confidence — active detection *corroborating* passive reasoning.

Design notes / known tactical costs:

* Both engines crawl independently, so a combined run fetches the target twice.
  The strategic refactor (make the legacy detectors injected pipeline stages)
  would share one crawl; this adapter deliberately keeps the two orchestrators
  intact for a low-risk, contained change.
* The legacy engine needs a live target and writes its own report as a side
  effect; the combined report is written last and wins. Legacy failures are
  swallowed so the combined run degrades to pipeline-only instead of erroring.
* Set ``run_legacy=False`` (or inject ``fetch``) to run the analysis/plumbing
  path fully offline — this is how the test suite exercises it without network.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from pipeline import Pipeline, PipelineConfig
from pipeline import dedup, normalization, reporting, validation
from pipeline.models import Finding

logger = logging.getLogger("dsg.combined")

# Legacy scan_url() result buckets -> canonical finding ``type``.
# Types are chosen to line up with the pipeline vocabulary (see
# pipeline/llm_analysis.py and pipeline/reporting.py) so identical issues
# corroborate on a shared fingerprint instead of duplicating.
_LEGACY_BUCKETS = {
    "xss_vulnerabilities": "XSS",
    "sql_vulnerabilities": "SQL Injection",
    "dom_xss": "DOM XSS",
    "csrf": "CSRF",
    "idor_vulnerabilities": "IDOR",
    "authorization_flaws": "Authorization",
    "parameter_exploitation": "Parameter Exploitation",
    "information_leakage": "Information Leakage",
    "open_redirects": "Open Redirect",
    "ssrf": "SSRF",
    "gemini_endpoint_analysis": "Gemini Endpoint Analysis",
    "gemini_stored_xss": "Stored XSS",
    "gemini_file_uploads": "File Upload",
    "gemini_attack_chains": "Attack Chain",
    "gemini_hidden_endpoints": "Hidden Endpoint",
}


def legacy_raw_findings(result: Dict) -> List[dict]:
    """Flatten a legacy ``scan_url()`` result dict into raw finding dicts.

    Each is tagged with a stable ``type`` (for fingerprinting) and a ``source``
    marking the engine, so the normalization/dedup stages can absorb them exactly
    like any other detector output.
    """
    raw: List[dict] = []
    for bucket, vuln_type in _LEGACY_BUCKETS.items():
        for item in result.get(bucket, []) or []:
            if not isinstance(item, dict):
                continue
            merged = dict(item)
            merged.setdefault("type", vuln_type)
            merged["source"] = "legacy-gemini" if bucket.startswith("gemini_") else "legacy-active"
            raw.append(merged)
    return raw


def _tag_engine(findings: List[Finding], engine: str) -> List[Finding]:
    for finding in findings:
        finding.metadata.setdefault("engine", engine)
    return findings


def run_combined(
    url: str,
    config: Optional[PipelineConfig] = None,
    gemini=None,
    fetch=None,
    run_legacy: bool = True,
    write: bool = True,
    reports_dir: str = "reports",
) -> Dict:
    """Run both engines and merge their findings into one unified report.

    Returns a report payload compatible with ``reporting.build_payload`` plus an
    ``engines`` breakdown of how many findings each engine contributed and how
    many survived deduplication.
    """
    cfg = config or PipelineConfig.from_env()

    # 1. Pipeline engine (passive/static + RAG-LLM). Suppress its own report;
    #    the combined report is authoritative.
    pipe_payload = Pipeline(config=cfg, fetch=fetch, gemini=gemini).run(url, write=False)
    pipeline_findings = _tag_engine(
        normalization.normalize(pipe_payload.get("normalized_findings", [])),
        "pipeline",
    )

    discovery = {
        "links": list(pipe_payload.get("links_found", [])),
        "js_endpoints": list(pipe_payload.get("js_endpoints", [])),
        "directories": list(pipe_payload.get("directories", [])),
        "subdomains": list(pipe_payload.get("subdomains", [])),
        "security_header_issues": list(pipe_payload.get("security_header_issues", [])),
        "cookie_issues": list(pipe_payload.get("cookie_issues", [])),
    }
    status_code = pipe_payload.get("status_code", 0)

    # 2. Legacy engine (active payload confirmation). Optional and best-effort:
    #    it needs a live target and may be slow, so failures never break the run.
    legacy_findings: List[Finding] = []
    if run_legacy:
        try:
            from scanner import scan_url

            legacy_result = scan_url(url)
            legacy_findings = _tag_engine(
                normalization.normalize(legacy_raw_findings(legacy_result)),
                "legacy",
            )
            # Fold legacy discovery into the combined report.
            for key in ("links", "js_endpoints", "directories", "subdomains"):
                src_key = "links_found" if key == "links" else key
                discovery[key] = sorted(
                    set(discovery[key]) | set(legacy_result.get(src_key, []) or [])
                )
            discovery["security_header_issues"] = (
                legacy_result.get("security_header_issues", []) or discovery["security_header_issues"]
            )
            discovery["cookie_issues"] = (
                legacy_result.get("cookie_issues", []) or discovery["cookie_issues"]
            )
            status_code = legacy_result.get("status_code", status_code) or status_code
        except Exception as exc:  # network-dependent; degrade to pipeline-only
            logger.warning("legacy engine skipped: %s", exc)

    # 3. Shared backbone: merge -> dedup (cross-engine corroboration) -> validate.
    deduped = dedup.deduplicate(pipeline_findings + legacy_findings)
    valid, rejected = validation.validate(
        deduped, drop_low_confidence=cfg.drop_low_confidence
    )

    # 4. One unified report.
    payload = reporting.build_payload(url, status_code, valid, discovery, rejected=rejected)
    if write:
        payload["reports"] = reporting.write_reports(payload, reports_dir)
    payload["engines"] = {
        "pipeline_findings": len(pipeline_findings),
        "legacy_findings": len(legacy_findings),
        "combined_unique": len(valid),
        "corroborated": sum(
            1 for f in valid if len(f.metadata.get("sources", []) or []) > 1
        ),
    }
    payload["stages_run"] = pipe_payload.get("stages_run", [])
    return payload
