# 🏗️ DSG_Suite — Architecture & Diagrams

Companion to [`README.md`](README.md). The README is the **narrated walkthrough**
(what every file does, detection techniques, limitations, interview crib sheet).
This file is the **map** — diagrams of how the pieces fit and how data flows.

Read the README for the "why"; skim this for the "shape".

---

## 1. System context

Who talks to whom.

```
        ┌──────────────┐        POST /scan            ┌───────────────────────────┐
        │  Next.js UI  │  ───────────────────────────▶│      Flask API (app.py)   │
        │ (frontend/)  │        POST /scan/pipeline   │  /scan · /scan/pipeline   │
        │  :3000       │◀───────────────────────────  │  /scan/combined           │
        └──────────────┘        JSON findings         │  /history · /reports/<f>  │
                                                       └────────────┬──────────────┘
                                                                    │
                                        ┌───────────────────────────┼───────────────────────────┐
                                        ▼                                                       ▼
                             ┌─────────────────────┐                            ┌────────────────────────┐
                             │  LEGACY ENGINE      │                            │  PIPELINE ENGINE       │
                             │  scanner.scan_url() │                            │  pipeline/Pipeline.run │
                             └──────────┬──────────┘                            └───────────┬────────────┘
                                        │                                                   │
                                        ▼                                                   ▼
                             ┌─────────────────────┐                            ┌────────────────────────┐
                             │  Target web app     │                            │  Google Gemini (LLM)   │
                             │  (HTTP via requests)│                            │  OR offline heuristics │
                             └─────────────────────┘                            └────────────────────────┘
                                        │                                                   │
                                        └──────────────────► reports/ ◀─────────────────────┘
                                                    report.html · report.json · findings.json
```

The LLM box is **optional** on both sides: pull `GEMINI_API_KEY` and the legacy
engine skips its Gemini stages while the pipeline swaps in deterministic regex
detectors. Findings are tagged by `source` so you can tell which layer produced them.

---

## 2. The two engines at a glance

```
                       ┌───────────────────────────── DSG_Suite ─────────────────────────────┐
                       │                                                                      │
   LEGACY (monolithic) │   scanner.scan_url()                                                 │
   ─────────────────── │   crawl → per-page scan → async XSS/SQLi → authz/IDOR → Gemini →     │
   feature-rich,       │   report_generator (HTML + JSON)                                     │
   sequential,         │                                                                      │
   LLM-dependent       │                                                                      │
                       │                                                                      │
   PIPELINE (staged)   │   pipeline.Pipeline.run()                                            │
   ─────────────────── │   11 injected, unit-tested stages · offline-capable · CI-covered     │
   recommended,        │   URL → … → RAG → LLM/heuristics → normalize → dedup → validate →    │
   testable,           │   report                                                             │
   deterministic       │                                                                      │
                       │                                                                      │
   COMBINED (adapter)  │   combined_scan.run_combined()                                       │
   ─────────────────── │   runs BOTH, merges every finding through the shared backbone →      │
   best of both:       │   normalize → dedup (cross-engine corroboration) → validate → report │
   depth + hygiene     │                                                                      │
                       └──────────────────────────────────────────────────────────────────────┘
```

All three are reachable from `app.py` (`/scan` = legacy, `/scan/pipeline` =
pipeline, `/scan/combined` = both merged) and share low-level helpers
(`payload_tester.session`, `report_generator`, the pipeline `Finding` model).

---

## 3. Legacy engine — `scan_url()` control flow

```
scan_url(url)
│
├─ find_subdomains(url)                 # inline HTTP brute (api/dev/test/staging)
├─ crawl_links(url)                     # BFS, MAX_DEPTH=3, MAX_LINKS=100, same-domain
│
├─ for each page:  scan_page(page) ─────┬─ scan_forms()          (form XSS/SQLi, method-aware)
│                                       ├─ scan_csrf()           (token/CORS/SameSite/login/AJAX)
│                                       ├─ scan_dom_xss()        (source→sink taint)
│                                       ├─ extract_js_endpoints()(regex /api /v1 /v2)
│                                       ├─ analyze_security_headers()
│                                       └─ analyze_cookies()
│
├─ dir_bruteforce(url)                  # forced browsing (COMMON_DIRS)
├─ test_open_redirect() / test_ssrf()   # reflection-based, per page
│
├─ asyncio.run(run_async_scan(pages))   # concurrent XSS/SQLi (aiohttp), 300s budget
│      └─ per URL: params OR gemini_param_generator → payload_tester.test_xss/test_sqli
│
├─ scan_idor_vulnerabilities()          ┐
├─ scan_authorization_flaws()           │  session-aware, differential-analysis
├─ scan_api_parameters()                │  modules (need SessionManager for multi-role)
├─ scan_response_anomalies()            ┘
│
├─ if Gemini available & not rate-limited:
│      scan_with_gemini_endpoint_analysis()   ┐
│      scan_stored_xss_with_gemini()          │  LLM as analyst:
│      scan_file_uploads_with_gemini()        │  reasoning, hotspots,
│      detect_workflow_chains_with_gemini()   │  attack chains,
│      identify_hidden_endpoints_with_gemini()┘  hidden endpoints
│
└─ generate_html_report() + generate_json_report() + save_json()
```

---

## 4. Pipeline engine — 11 stages with data shapes

```
                 str (URL)
                    │
   [1] crawler.py ──┴──────────────▶  List[str]  (same-domain URLs, BFS)
                    │
   [3] js_extraction.py ────────────▶ List[JSAsset]   (external + inline <script>)
                    │  mine_endpoints()
                    ▼
   [2] endpoint_discovery.py ───────▶ List[Endpoint]  (url, method, params, source)
                    │
   [4] unminify.py  ────────────────▶ List[JSAsset]   (beautified, webpack-split)
                    │
   [5] chunking.py  ────────────────▶ List[Chunk]     (overlapping windows: js/html/endpoint)
                    │
   [6] rag.py       ────────────────▶ TfidfRetriever  (fit on chunks; query per vuln class)
                    │
   [7] llm_analysis.py ─────────────▶ List[dict]      (raw findings — gemini-rag OR heuristic-rag)
                    │        ▲
                    │        └── DETECTORS: DOM XSS · Hardcoded Secret · Insecure Transport · IDOR
                    │
   [8] normalization.py ────────────▶ List[Finding]   (canonical shape + fingerprint)
                    │
   [9] dedup.py     ────────────────▶ List[Finding]   (merged; corroboration → confidence↑)
                    │
   [10] validation.py ──────────────▶ (accepted, rejected)   (quality gate; rejects kept w/ reason)
                    │
   [11] reporting.py ───────────────▶ payload dict → reports/findings.json (+ legacy html/json)
```

> Note the numbering: **JS extraction (3) runs before endpoint discovery (2)** in
> `orchestrator.py` so paths mined from JavaScript enrich the endpoint set.

### Injection points (why it's testable)
```
Pipeline(config, fetch, gemini)
          │       │      └── LLM: real GeminiAnalyzer | FakeGemini | None → heuristics
          │       └───────── HTTP: real session | in-memory SITE dict (tests)
          └───────────────── knobs: PipelineConfig.from_env()  (DSG_* env vars)
```

---

## 5. Combined engine — merging both (`run_combined`)

The tactical adapter that gets depth **and** hygiene: run both engines, then push
every finding through the pipeline's shared backbone so they converge on one
report with one confidence model.

```
   ┌─────────────────────────┐   passive/static + RAG-LLM findings
   │  Pipeline.run(write=0)   │ ─────────────┐   source: heuristic-rag | gemini-rag
   └─────────────────────────┘              │
                                            ▼
                                     ┌──────────────┐
   ┌─────────────────────────┐       │ normalize    │  heterogeneous dicts → Finding
   │  scanner.scan_url()      │       │   (shared)   │
   │  (active, payload-       │ ────▶ ├──────────────┤
   │   confirmed findings)    │       │ dedup        │  same fingerprint (type|url|param)?
   └─────────────────────────┘       │   ┌────────┐ │  → merge, keep strongest severity,
       source: legacy-active         │   │CORROB. │ │    and if sources differ across
               legacy-gemini         │   │ boost  │ │    engines → confidence = HIGH
                                     │   └────────┘ │
                                     ├──────────────┤
                                     │ validate     │  drop junk; keep rejects w/ reason
                                     ├──────────────┤
                                     │ reporting    │  ONE unified findings.json + html
                                     └──────┬───────┘
                                            ▼
                          payload + engines: {pipeline_findings, legacy_findings,
                                              combined_unique, corroborated}
```

**The value:** an LLM-reasoned "this endpoint looks injectable" (`gemini-rag`) and
an actively-confirmed SQLi (`legacy-active`) that share a fingerprint collapse
into **one** finding whose confidence is raised because two independent engines
agree. Passive triage + active confirmation, scored by consensus.

**Offline testability:** `run_combined(run_legacy=False, fetch=<injected>)` runs
the whole merge path with no network — that's how `test_combined.py` exercises it
in CI. The legacy half is best-effort; if it errors (needs a live target) the run
degrades to pipeline-only.

**Known tactical cost:** both engines crawl independently → the target is fetched
twice. The strategic version makes the legacy detectors *injected pipeline stages*
sharing one crawl (and lets RAG/LLM triage decide which endpoints get actively
tested); this adapter keeps both orchestrators intact for a contained change.

---

## 6. The AI data-flow (RAG)

How a single vulnerability class gets analyzed in stage 7.

```
  vuln class "DOM XSS"
        │
        │  query = "innerHTML document.write eval ... location.hash sink"
        ▼
  ┌──────────────┐   top-k chunks    ┌──────────────────────────────────────────┐
  │ TfidfRetriever│ ───────────────▶ │  most relevant code windows only          │
  │  (rag.py)     │                  │  (NOT the whole minified bundle)          │
  └──────────────┘                  └───────────────┬──────────────────────────┘
                                                     │
                             ┌───────────────────────┴───────────────────────┐
                             ▼                                                ▼
              gemini available?  YES                            gemini available?  NO
                             │                                                │
        ┌────────────────────▼─────────────────────┐          ┌───────────────▼────────────────┐
        │ GeminiAnalyzer.analyze_endpoint(context) │          │ regex DETECTORS over same chunks │
        │  → JSON (regex-extracted, schema-coerced)│          │  → deterministic findings        │
        │  source = "gemini-rag"                   │          │  source = "heuristic-rag"        │
        └────────────────────┬─────────────────────┘          └───────────────┬────────────────┘
                             │   (empty? fall back ─────────────────────────────┘ safety net)
                             ▼
                       raw finding dicts
```

Key idea: **retrieval keeps the prompt small and focused**, and the heuristic path
guarantees output even with no API key. Both feed the same normalization stage.

---

## 7. Finding lifecycle (how noise becomes a report)

```
  heterogeneous dicts                canonical                merged                gated
  {endpoint, risk_level,   ┌──────┐  Finding      ┌──────┐   Finding    ┌────────┐  accepted ──▶ report
   explanation, ...}  ────▶│normal│──(fingerprint)│dedup │──(source set)│validate│
  {url, severity,          │-ize  │   type|url|param│      │  conf↑ if   │        │  rejected ──▶ kept
   evidence, ...}     ────▶└──────┘               └──────┘  corroborated └────────┘  (with reason)
```

- **Fingerprint** = `sha1("type|normalized_url|parameter")[:16]` → same weakness,
  same place = one finding.
- **Corroboration**: regex + LLM agreeing on a fingerprint bumps confidence to `high`.
- **Validation** drops findings with no type / no anchor, optionally drops
  low-confidence, and **retains rejects with reasons** (auditability).

---

## 8. Module dependency map (backend)

```
app.py  (/scan · /scan/pipeline · /scan/combined)
  ├─ scanner.py ───────────┬─ async_scanner.py ─── payload_tester.py  (XSS/SQLi engine, shared session)
  │                        │                   └── gemini_param_generator.py  (AI param discovery)
  │                        ├─ form_scanner.py ───── payload_tester.py
  │                        ├─ csrf_scanner.py
  │                        ├─ dom_xss_scanner.py
  │                        ├─ js_endpoint_extractor.py
  │                        ├─ idor_scanner.py ─────┐
  │                        ├─ authorization_scanner.py ─┼─ session_manager.py  (multi-identity)
  │                        ├─ api_parameter_mutator.py ─┘
  │                        ├─ response_analyzer.py
  │                        ├─ gemini_analyzer.py   (LLM reasoning engine)
  │                        ├─ report_generator.py  (HTML/JSON output)
  │                        └─ pipeline/  ────────── orchestrator → 11 stage modules
  │                                                 (models.py · config.py shared)
  └─ combined_scan.py ─────┬─ pipeline/  (normalize · dedup · validate · reporting — shared backbone)
                           └─ scanner.scan_url()  (lazy import; legacy active detectors)
```

Note: subdomain and directory brute-forcing live **inline** in `scanner.py`
(`find_subdomains`, `COMMON_DIRS`) rather than as separate modules. `combined_scan.py`
depends on both `pipeline` and (lazily) `scanner`; the `pipeline` package has **no**
back-dependency on legacy code, so it stays self-contained and offline-testable.

---

## 9. Test & CI topology

```
  backend/tests/conftest.py
     ├─ SITE dict  (in-memory vulnerable site → injected as `fetch`)
     └─ FakeGemini (canned LLM → injected as `gemini`)
              │
              ▼
  one suite per stage  +  test_orchestrator.py (end-to-end, asserts stage order)
              │
              ▼
  .github/workflows/ci.yml
     ├─ backend : flake8 + pytest --cov   (Py 3.10/3.11/3.12, DSG_USE_LLM=0)
     ├─ frontend: npm ci → lint → next build
     └─ deploy  : (main push) docker build → placeholder
```

Everything runs **offline and deterministic** — no network, no API key — which is
exactly what makes the pipeline the demonstrable, trustworthy half of the suite.
