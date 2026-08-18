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
        │  :3000       │◀───────────────────────────  │  /scan/agentic            │
        └──────────────┘        JSON findings         │  /history · /reports/<f>  │
                                                       └────────────┬──────────────┘
                                                                    │  preset = config toggles
                                                                    ▼
                                                       ┌────────────────────────────┐
                                                       │   pipeline/Pipeline.run     │
                                                       │  Scope→Collect→Evidence→RAG │
                                                       │  →Analyze→[Active]→backbone │
                                                       │  →[Verify]→report           │
                                                       └───────┬────────────┬────────┘
                                        ┌──────────────────────┘            └──────────────────┐
                                        ▼                                                       ▼
                             ┌─────────────────────┐                            ┌────────────────────────┐
                             │  Target web app     │  browser (Playwright)      │  Groq (LLM)            │
                             │  or requests        │  · detector library        │  OR offline heuristics │
                             └─────────────────────┘                            └────────────────────────┘
                                        │                                                   │
                                        └──────────────────► reports/ ◀─────────────────────┘
                                            report.html · report.json · findings.json · dashboard.html
```

The LLM box is **optional**: pull `GROQ_API_KEY` and the analyze stage swaps the
agent for deterministic heuristics. Findings are tagged by `source`
(`agentic` · `evidence` · `active` · `heuristic-rag`) so you can tell which layer
produced them.

---

## 2. One pipeline, three presets

```
                    ┌───────────────────────────── DSG_Suite ─────────────────────────────┐
                    │                    pipeline.Pipeline.run()                           │
                    │   Scope → Collect → Evidence → RAG → Analyze → [Active] → backbone   │
                    │           → [Verify] → report      (all stages injected/testable)    │
                    ├──────────────────────────────────────────────────────────────────────┤
  LIGHTWEIGHT       │   run_pipeline · /scan/pipeline    requests · no payloads · no browser│
  ACTIVE            │   scan_url     · /scan             requests · + active payload testing│
  FULL              │   run_agentic  · /scan/agentic     browser · + active + verification  │
                    └──────────────────────────────────────────────────────────────────────┘
```

Presets are just `PipelineConfig` toggles (`prefer_browser`, `active_testing`,
`verify_findings`). The old monolithic `scan_url` and `combined_scan` are gone —
folded into the pipeline. The specialized detectors remain as a **library** the
active stage calls.

---

## 3. The detector library (driven by the active stage)

The deep active detectors are standalone modules; the pipeline's active-testing
stage ([`active.py`](backend/pipeline/active.py)) drives them over the in-scope,
non-destructive endpoints/forms the pipeline already discovered — one crawl, no
separate orchestrator.

```
evidence.endpoints / forms ──▶ ActiveTester.run() ──▶ raw findings (source="active")
     (in-scope, non-destructive)      │
                                      ├─ payload_tester.test_xss / test_sqli   (reflected XSS · 4-family SQLi)
                                      ├─ idor_scanner.IDORScanner.test_idor    (numeric-ID mutation + diff)
                                      └─ ssrf / open-redirect probes           (localhost / off-site reflection)
```

Still available as a library (not yet wired into the active stage): `form_scanner`,
`csrf_scanner`, `authorization_scanner`, `api_parameter_mutator`, `response_analyzer`.

---

## 4. Pipeline engine — stages with data shapes

```
                 str (URL)
                    │
   [1] scope.py     ────────────────▶ Scope            (host allowlist, read-only, max_pages)
                    │
   [2] collectors/  ────────────────▶ List[PageCapture] (DOM · JS bodies · network · storage · forms)
                    │                                    (Playwright | requests fallback)
   [3] evidence.py  ────────────────▶ Evidence          (typed, REDACTED inventories)
                    │  baseline_findings()               + List[dict] deterministic "facts"
                    ▼
   [4] chunking + unminify + rag ───▶ TfidfRetriever    (redacted DOM/JS + evidence chunks)
                    │
   [5] agent/ (loop·tools) ─────────▶ List[dict], trace  (bounded tool-loop → source=agentic)
                    │        ▲                            (no key → llm_analysis heuristics)
                    │        └── evidence forms: dom_sinks · endpoints · forms · network_map · secrets
                    │
   [5b] active.py   ────────────────▶ List[dict]         (opt-in: payloads → source=active)
                    │  payload_tester · idor_scanner · ssrf/redirect  (in-scope, non-destructive)
                    │
   [6] normalization → dedup → validation
                    │            ────▶ (accepted, rejected)  (canonical · merged · quality-gated)
                    │
   [6b] verify.py   ────────────────▶ findings +verified    (opt-in: benign browser canary → PoC)
                    │
   [7] reporting.py ────────────────▶ payload → findings.json · report.html · dashboard.html
```

> Deterministic collection + shaping on the left; the agent is the single AI stage;
> active payload testing and browser verification are optional; then the shared backbone.

### Injection points (why it's testable)
```
Pipeline(config, collector|fetch, groq, probe, active)
          │       │                │     │      └── active: real detectors | fake tester (tests)
          │       │                │     └── verify: real browser | fake probe (tests)
          │       │                └──────── LLM: GroqAnalyzer | FakeGroqAgent | None → heuristics
          │       └───────────────────────── collect: Playwright | RequestsCollector(fetch=SITE)
          └───────────────────────────────── knobs: PipelineConfig.from_env()  (DSG_* env vars)
```

---

## 5. Corroboration — active + agent findings on one fingerprint

There is no separate "combined engine" any more: the active detectors run **as a
stage** of the one pipeline, so their findings and the agent's share the backbone
directly. Corroboration falls out for free.

```
   agent / evidence findings ──┐   source: agentic | evidence | heuristic-rag
                               ├─▶ normalize ─▶ dedup ─▶ validate ─▶ ONE report
   active-stage findings ──────┘        │  same fingerprint (type|url|param)?
       source: active                   └─ merge · keep strongest severity ·
       (payload-confirmed)                 sources differ → confidence = HIGH
```

**The value:** an agent's "this endpoint looks injectable" (`agentic`) and an
actively-confirmed SQLi (`active`) that share a fingerprint collapse into **one**
finding whose confidence is raised because two independent methods agree — passive
triage + active confirmation, scored by consensus, in a single crawl.

---

## 5b. Full client-side preset — `Pipeline.run` with browser + verify

This is the **same** `Pipeline` as §4, run with `prefer_browser` + `verify_findings`
on (`run_agentic`). The guiding split: **data retrieval and processing are
deterministic; only the analysis is agentic.** A real browser gathers the
client-side surface, deterministic shaping turns it into typed evidence "forms", a
bounded Groq tool-agent reasons over that corpus behind a hard boundary, and a
final browser stage autonomously *confirms* the bugs.

```
 seed URL
   │
   ▼
┌───────────────┐   scope allowlist + read-only are enforced at the browser edge
│  Scope        │   (only in-scope hosts navigated; POST/PUT/PATCH/DELETE aborted)
│  (scope.py)   │
└──────┬────────┘
       ▼
┌──────────────────────────┐   Playwright (headless Chromium) renders each page,
│  Collector               │   executing its JS → PageCapture per page:
│  Playwright | requests   │   rendered DOM · JS bodies · network log · cookies ·
│  (collectors/)           │   localStorage/sessionStorage · console · forms
└──────┬───────────────────┘   (no browser → requests fallback: DOM only)
       ▼
┌──────────────────────────┐   deterministic shaping → compact typed inventories,
│  Evidence shaping        │   REDACTED (redaction.py) before they can reach a model:
│  (evidence.py)           │   endpoints · forms · dom_sinks · network_map ·
│                          │   storage · security_headers · secrets
│  → baseline_findings()   │   + deterministic "facts" findings (source=evidence)
└──────┬───────────────────┘
       ▼
┌──────────────────────────┐   redacted DOM/JS chunks + evidence chunks
│  Chunk + RAG (rag.py)    │
└──────┬───────────────────┘
       ▼
┌──────────────────────────┐   bounded ReAct loop over READ-ONLY tools
│  Agentic analyzer        │   (rag_search · get_evidence · read_source);
│  (agent/loop.py+tools.py)│   budgets: max_agent_steps · max_tool_calls · wall-clock
│                          │   report_finding → source=agentic
│  no key → heuristics     │   empty → heuristic safety-net
└──────┬───────────────────┘
       ▼
   normalize → dedup (agentic ⨝ evidence corroborate) → validate
       │
       ▼
┌──────────────────────────┐   opt-in: drive Playwright with a BENIGN canary to
│  Verify (verify.py)      │   confirm XSS-class findings. Executes? → verified=true,
│  in-scope · GET · benign │   confidence=high, PoC url. Else kept, flagged unconfirmed.
└──────┬───────────────────┘
       ▼
   reporting → findings.json + report.html + dashboard.html
               (findings +✓verified · evidence · network map · agent trace)
```

**The boundary (four controls):** scope allowlist + read-only (`scope.py`,
enforced by the browser route-abort — verification probes are in-scope, benign,
GET-only), resource budgets (`agent/loop.py`), and secret redaction
(`redaction.py`) applied to every form/chunk *before* Groq.

**Why a browser:** a `requests` fetch sees only server HTML. Playwright sees the
*runtime* — JS-injected links, XHR/fetch traffic, and `localStorage` tokens — which
is exactly where modern client-side risk lives.

**Offline testability:** the collector and `groq` are injected. `RequestsCollector`
+ a scripted `FakeGroqAgent` (see `conftest.py`) exercise the whole path — scope
gating, redaction, shaping, budgets, agent tool-loop, fallback — with no network
and no browser.

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
              groq available?  YES                            groq available?  NO
                             │                                                │
        ┌────────────────────▼─────────────────────┐          ┌───────────────▼────────────────┐
        │ GroqAnalyzer.analyze_endpoint(context)   │          │ regex DETECTORS over same chunks │
        │  → JSON (regex-extracted, schema-coerced)│          │  → deterministic findings        │
        │  source = "groq-rag"                     │          │  source = "heuristic-rag"        │
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
app.py  (/scan · /scan/pipeline · /scan/agentic)
  └─ scanner.py  (thin presets: scan_url · scan_url_pipeline · scan_url_agentic)
        └─ pipeline/ ── orchestrator.py = the one Pipeline
              ├─ scope.py · redaction.py             (boundary)
              ├─ collectors/ (browser·base)          (Playwright | requests)
              ├─ evidence.py                         (deterministic shaping)
              ├─ chunking.py · rag.py · unminify.py  (context prep)
              ├─ agent/ (loop·tools) ── groq_analyzer.py  (bounded Groq tool-loop)
              ├─ active.py ──┬─ payload_tester.py    (context XSS · 4-family SQLi)
              │              ├─ idor_scanner.py ──── session_manager.py
              │              └─ (ssrf / open-redirect probes)
              ├─ verify.py                           (browser bug confirmation)
              ├─ dashboard.py · report_generator.py  (dashboard + legacy HTML/JSON)
              ├─ models.py · config.py               (shared)
              └─ normalize · dedup · validate · reporting   (shared backbone)

detector library (standalone; some not yet wired into active.py):
  form_scanner · csrf_scanner · dom_xss_scanner · authorization_scanner ·
  api_parameter_mutator · response_analyzer · js_endpoint_extractor · async_scanner
```

Notes: `scanner.py` is now just three preset wrappers over `Pipeline`; the old
monolith and `combined_scan.py` are gone. The `pipeline` package has **no**
back-dependency on `scanner`, so it stays self-contained and offline-testable.
Playwright is imported lazily inside `collectors/browser.py` (and `verify.py`), so
`import pipeline` never requires the browser stack.

---

## 9. Test & CI topology

```
  backend/tests/conftest.py
     ├─ SITE dict  (in-memory vulnerable site → injected as `fetch`)
     ├─ FakeGroq (canned LLM → injected as `groq`)
     └─ FakeGroqAgent + RequestsCollector (scripted tool-loop + offline capture)
              │
              ▼
  one suite per stage (scope · redaction · collectors · evidence · agent · active ·
     verify) + test_orchestrator.py / test_agentic.py (end-to-end, assert stage order)
              │
              ▼
  .github/workflows/ci.yml
     ├─ backend : flake8 + pytest --cov   (Py 3.10/3.11/3.12, DSG_USE_LLM=0)
     ├─ frontend: npm ci → lint → next build
     └─ deploy  : (main push) docker build → placeholder
```

Everything runs **offline and deterministic** — no network, no API key — which is
exactly what makes the pipeline the demonstrable, trustworthy half of the suite.
