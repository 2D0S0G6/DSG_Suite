# 🚀 DSG_Suite — AI-Assisted Web Vulnerability Scanner

> A learning-grade web application security scanner that pairs **classical
> deterministic detection** (regex/signature/differential analysis) with an
> **LLM reasoning layer** (Google Gemini) wired into a **RAG pipeline**.
> Built to demonstrate how AI is applied to security analysis — and where AI
> should *not* be trusted blindly.

This README is intentionally long. It is written to be **read top-to-bottom as a
study guide**: it explains what the tool solves, how every stage works, what
each file does, the detection technique behind every vulnerability class, and an
honest list of limitations. If you are walking an interviewer through this repo,
the [Interview crib sheet](#-interview-crib-sheet) at the bottom is your one-page
summary.

📐 **Companion doc:** [`ARCHITECTURE.md`](ARCHITECTURE.md) holds the diagrams —
system context, both engines, the 11-stage pipeline with data shapes, the AI/RAG
data-flow, and the module dependency map. This README is the words; that file is
the pictures. Together they are the only two docs in the repo.

---

## 📑 Table of contents

1. [What problem it solves](#-what-problem-it-solves)
2. [The two engines](#-the-two-engines-legacy-vs-pipeline)
3. [The AI-security story (read this for the interview)](#-the-ai-security-story)
4. [How a scan actually runs (end-to-end)](#-how-a-scan-actually-runs)
5. [The analysis pipeline, stage by stage](#-the-analysis-pipeline-stage-by-stage)
6. [Vulnerability classes & the detection technique behind each](#-vulnerability-classes--detection-techniques)
7. [Complete file-by-file reference](#-complete-file-by-file-reference)
8. [Install & run](#-install--run)
9. [Configuration](#-configuration)
10. [Testing](#-testing)
11. [CI/CD & Docker](#-cicd--docker)
12. [Limitations & known gaps (be honest about these)](#-limitations--known-gaps)
13. [Interview crib sheet](#-interview-crib-sheet)
14. [Glossary](#-glossary)
15. [Legal & ethical disclaimer](#-legal--ethical-disclaimer)

---

## 🎯 What problem it solves

Traditional vulnerability scanners are **signature-based**: they fire a payload,
match a regex, and report a hit. They are precise but "dumb" — they cannot reason
about **business logic** (e.g. "can a student read another student's marks?"),
they cannot **chain** individually-benign steps into an exploit, and they choke on
**minified/obfuscated JavaScript** where secrets and DOM-XSS sinks hide.

DSG_Suite's thesis: **combine both worlds.**

| Layer | What it's good at | Files |
|-------|-------------------|-------|
| **Deterministic scanners** | High-precision, evidence-backed findings (SQLi error signatures, reflected XSS in executable context, IDOR via response diff) | `payload_tester.py`, `idor_scanner.py`, `authorization_scanner.py`, `response_analyzer.py`, `api_parameter_mutator.py` |
| **AI reasoning layer** | Context/logic flaws, attack-chain synthesis, hidden-endpoint discovery, smart parameter guessing | `gemini_analyzer.py`, `gemini_param_generator.py`, `pipeline/llm_analysis.py` |

The AI **augments** the scan; it never **gates** it. Pull the API key and the
whole suite still runs on deterministic heuristics — a property proven in CI.

**Target use:** intentionally vulnerable apps (DVWA, WebGoat, `demo.testfire.net`),
localhost, or apps you own. It is a teaching/demonstration tool, not a production
pentest platform.

---

## 🧭 The engines (legacy · pipeline · combined)

The repo contains **two independent scan engines** plus a **combined adapter**
that merges them. Knowing which is which prevents confusion when reading the code.

### 1. Legacy scanner — `scanner.scan_url()`
The original monolithic scan. One big function crawls the site, fans out every
specialized scanner per page, runs async injection testing, layers on the
authorization/IDOR modules, then calls Gemini for AI findings, and finally emits
HTML + JSON reports. It is feature-rich but sequential, hard to test, and depends
heavily on the live Gemini service for its "AI" findings.

```
scan_url(url)
 → find_subdomains → crawl_links (BFS, depth 3, ≤100 links)
 → for each page: scan_page → {forms, csrf, dom_xss, js_endpoints, headers, cookies}
 → dir_bruteforce → test_open_redirect / test_ssrf
 → asyncio.run(run_async_scan(pages))        # concurrent XSS/SQLi, 300s budget
 → scan_idor / scan_authorization / scan_api_parameters / scan_response_anomalies
 → Gemini: endpoint analysis, stored-XSS hotspots, uploads, attack chains, hidden endpoints
 → generate_html_report + generate_json_report + save_json
```

### 2. Staged analysis pipeline — `pipeline/` (recommended)
A modular, **dependency-injected** re-implementation. Each stage is a discrete,
unit-tested module. Network fetch and the LLM are **injected**, so the entire
pipeline runs in tests against an in-memory site with **no network and no API
key**. This is the path covered by the test suite and CI, and the one to show off.

```
URL → Crawler → Endpoint discovery → JS extraction → Unminify/unbundle
    → Chunk/context gen → RAG (TF-IDF) → LLM analysis (Gemini OR heuristics)
    → Normalization → Deduplication → Validation → JSON/HTML report
```

### 3. Combined engine — `combined_scan.run_combined()`
The two engines are strong in opposite halves: the **pipeline** has excellent
*plumbing* (DI, RAG, `normalize → dedup → validate → report`) but shallow
detectors; the **legacy** engine has deep *active* detectors (payload-confirmed
XSS/SQLi, multi-role authz, active IDOR) but no finding hygiene. The combined
adapter runs both and funnels **every** finding through the pipeline's shared
backbone, so they converge on one canonical `Finding` stream and one report.

```
   pipeline findings ─┐
                      ├─▶ normalize ─▶ dedup ─▶ validate ─▶ ONE unified report
   legacy findings  ──┘        (cross-engine corroboration: an active-confirmed
                               finding + an LLM-reasoned one on the same
                               fingerprint merge and get confidence-boosted)
```

Why it's *better* than either alone: when a regex-confirmed SQLi and an LLM
"this endpoint looks injectable" land on the same fingerprint, [`dedup.py`](backend/pipeline/dedup.py)
merges them and bumps confidence to `high` — active detection **corroborating**
passive reasoning. The report's `engines` block shows each engine's contribution
and how many findings were corroborated across both.

> **Tactical costs (documented, by design):** the two engines crawl
> independently, so a combined run fetches the target twice; the legacy half
> needs a live target and is best-effort (failures degrade to pipeline-only). The
> *strategic* version — making the legacy detectors injected pipeline stages that
> share one crawl — is the natural next step; this adapter keeps both
> orchestrators intact for a low-risk, contained change.

All three are reachable from the Flask API and CLI (see [Install & run](#-install--run)).

---

## 🤖 The AI-security story

This is the part interviewers care about. Six themes run through the codebase.

### 1. RAG (Retrieval-Augmented Generation) — grounding the LLM
Minified bundles are huge; you cannot (and should not) dump an entire JS bundle
into an LLM prompt. Instead:

- **Chunk** JS/HTML/endpoints into overlapping windows (`chunking.py`). Overlap
  preserves context that would otherwise be split across a boundary — e.g. a
  DOM sink and the variable feeding it.
- **Retrieve** only the most relevant chunks per vulnerability class with a
  **pure-Python TF-IDF + cosine-similarity retriever** (`rag.py`). No numpy, no
  faiss, no embedding service — so retrieval is deterministic and CI-friendly.
- **Augment** the prompt: for the query
  `"innerHTML document.write eval ... location.hash sink"` the retriever returns
  the chunks most likely to contain a DOM-XSS sink, and only those go to the model.

**Why this matters:** small, focused prompts → lower cost, tighter answers, and a
smaller hallucination surface. This is textbook RAG applied to source-code
security review.

### 2. Two distinct roles for the LLM
- **LLM as analyst/reasoner** (`gemini_analyzer.py`): infers endpoint purpose,
  reasons about IDOR/authorization/logic flaws, predicts stored-XSS hotspots,
  and **synthesizes multi-step attack chains** ("submit form → stored → rendered
  in admin panel → XSS fires against an admin"). This is reasoning a regex cannot do.
- **LLM as offensive input generator** (`gemini_param_generator.py`,
  `async_scanner.generate_parameters`): when a URL exposes no parameters, the
  model *predicts likely parameter names* to fuzz — AI-augmented content
  discovery that beats a static wordlist.

### 3. Graceful degradation / defense-in-depth
Every LLM path checks `is_available()` / `is_rate_limited()` and falls back:
- No API key → `pipeline/llm_analysis.py` runs deterministic RAG-driven regex
  detectors instead, so the pipeline **always** produces findings.
- `gemini_param_generator` falls back to `DEFAULT_COMMON_PARAMS`.
- The legacy scanner simply skips its Gemini stages.

Set `DSG_USE_LLM=0` to force the offline path. CI runs this way to stay
deterministic. Findings are **tagged by source** (`gemini-rag` vs
`heuristic-rag`) so a reviewer can weigh probabilistic vs deterministic evidence.

### 4. Defensive handling of untrusted model output
LLMs return free-form text, sometimes wrapped in prose/markdown. The code treats
model output as **untrusted input**:
- **JSON extraction by regex** (`re.search(r'\{.*\}', ...)` + `json.loads`) so a
  model that wraps JSON in explanation still parses.
- **Schema coercion** (`normalization.py`): heterogeneous detector dicts
  (`endpoint` vs `url`, `risk_level` vs `severity`) are mapped onto one canonical
  `Finding` shape, with severity/confidence vocabularies normalized.
- **A validation gate** (`validation.py`): rejects findings with no type or no
  anchor (neither URL nor evidence), and can drop low-confidence noise — **keeping
  the rejects with reasons** so nothing disappears silently. This is a guard
  against noisy/hallucinated LLM output.

### 5. Multi-detector corroboration raises trust
`dedup.py` collapses findings that share a fingerprint (type + normalized URL +
parameter). When an independent source corroborates (a regex scanner **and** the
LLM flag the same thing), confidence is bumped to `high`. Consensus = trust.

### 6. False-positive reduction as a first-class concern
The deterministic engine is engineered for **precision**, not just recall:
- **Context-aware XSS** (`payload_tester.py`): inject a benign **canary**, detect
  *where* it reflected (script body / attribute / HTML text), check the payload
  came back **un-encoded** and in an **executable context**, and that response
  length is within 50% of baseline (avoids WAF/error pages) before reporting.
- **SQLi with guards**: error-based needs corroborating keywords, union-based
  needs length + data-token thresholds, boolean-blind needs a large length delta
  between TRUE/FALSE payloads, time-based needs **≥2 confirmations** at a 6s
  threshold (network-latency guard).
- **LLM self-rating**: prompts demand a `confidence` field and "be realistic".

### ⚠️ AI-security risks the codebase itself illustrates (great talking points)
- **Prompt-injection / trusting model output as attack input.** `generate_parameters`
  feeds LLM-produced strings straight into HTTP requests without validation. A
  hostile page could, in principle, influence what the scanner requests.
- **Safety-filter suppression.** `gemini_analyzer._safe_generate` sets
  `HARM_CATEGORY_DANGEROUS_CONTENT`/`HARASSMENT` to `BLOCK_NONE` because exploit
  text trips content filters — a legitimate offensive-security need, but a
  deliberate loosening of the model's guardrails worth calling out.
- **Output-handling irony.** `report_generator.py` interpolates finding evidence
  into HTML via f-strings **without escaping** — so the vuln report itself is
  self-XSS-able if rendered with attacker-controlled evidence.
- **Non-determinism.** LLM findings vary run-to-run (`temperature=0.7`); the
  deterministic layer and `source` tagging exist partly to contain this.

---

## 🔄 How a scan actually runs

### Via the pipeline (recommended)
```python
from pipeline import Pipeline, PipelineConfig
from gemini_analyzer import GeminiAnalyzer

gemini = GeminiAnalyzer()
result = Pipeline(
    config=PipelineConfig.from_env(),
    gemini=gemini if gemini.is_available() else None,   # injected, optional
).run("https://demo.testfire.net")

print(result["summary"])              # per-severity counts
print(result["normalized_findings"])  # flat canonical findings
```

`orchestrator.py::Pipeline.run()` executes the stages in order, logging each into
`self.stages` for observability, and returns a payload compatible with the legacy
report generator **plus** `normalized_findings`, `rejected_findings`, and
`stages_run`.

### Via the combined engine (both engines, one report)
```python
from scanner import scan_url_combined
result = scan_url_combined("https://demo.testfire.net")
print(result["engines"])              # {pipeline_findings, legacy_findings, combined_unique, corroborated}
print(result["normalized_findings"])  # merged + deduplicated across both engines
```

### Via the Flask API
```bash
python backend/app.py                      # Flask on :5000
curl -X POST localhost:5000/scan/pipeline \
     -H 'Content-Type: application/json' \
     -d '{"url":"https://demo.testfire.net"}'
# or /scan/combined for the merged report from both engines
```

### Via the CLI (legacy engine)
```bash
python backend/app.py https://demo.testfire.net
```

### Via the frontend
The Next.js UI (`frontend/`) POSTs to the backend and renders severity-colored
finding cards. (Note: the page currently calls `http://localhost:5000/scan`
directly and relies on CORS; a built-in `/api/scan` proxy route exists but is
unused — see [Limitations](#-limitations--known-gaps).)

---

## 🧩 The analysis pipeline, stage by stage

Each row is one module under [`backend/pipeline/`](backend/pipeline/). Shared
dataclasses live in `models.py`; env-overridable knobs in `config.py`.

| # | Stage | Module | What it does | Key technique |
|---|-------|--------|--------------|---------------|
| 1 | **Crawler** | `crawler.py` | BFS, same-domain, from a start URL | FIFO queue of `(url, depth)`; injected `fetch`; BeautifulSoup link extraction |
| 2 | **Endpoint discovery** | `endpoint_discovery.py` | Crawled URLs + JS-mined paths → unique `Endpoint`s with method+params | `parse_qsl` param extraction; `/api/`, `/v\d+/`, `/graphql`, `/rest/` regexes |
| 3 | **JS extraction** | `js_extraction.py` | Collect external `<script src>` (fetched, deduped) + inline scripts; mine endpoint paths | BeautifulSoup + regex mining |
| 4 | **Unminify/unbundle** | `unminify.py` | Beautify JS; split webpack bundles into per-module units | `jsbeautifier` (optional) or regex fallback; `(\d+)\s*:\s*function\s*\(` module split |
| 5 | **Chunk/context gen** | `chunking.py` | Break assets/pages/endpoints into overlapping windows | Sliding window, `step = size - overlap` |
| 6 | **RAG** | `rag.py` | Retrieve top-k relevant chunks per query | Pure-Python **TF-IDF + cosine similarity**, smoothed IDF |
| 7 | **LLM analysis** | `llm_analysis.py` | Per vuln class: query → retrieve → analyze (Gemini or heuristics) | RAG + duck-typed LLM; regex detectors as fallback/safety-net |
| 8 | **Normalization** | `normalization.py` | Map any detector dict → canonical `Finding` | Priority-ordered key picking; severity aliasing; fingerprinting |
| 9 | **Deduplication** | `dedup.py` | Merge same-fingerprint findings; boost corroborated confidence | SHA1 fingerprint (type+url+param); source-set union |
| 10 | **Validation** | `validation.py` | Drop invalid/low-confidence; keep rejects with reasons | Structural gate + optional confidence threshold |
| 11 | **Reporting** | `reporting.py` | Build payload; write `findings.json`; best-effort legacy HTML/JSON | Type→bucket mapping; severity rollups |

**Design principles:** dependency injection (fetch + LLM injected), offline by
default (heuristics when Gemini is absent), no heavy ML deps (pure-Python RAG).

---

## 🛡️ Vulnerability classes & detection techniques

| Class | How it's detected | Where |
|-------|-------------------|-------|
| **Reflected XSS** | Canary injection → context classification (script/attribute/HTML) → context-specific payload → validate un-encoded + executable + length-sane | `payload_tester.py::test_xss` |
| **DOM XSS** | Static **source→sink taint matching** on client JS; user sources (`location.hash`, `postMessage`, …) flowing into sinks (`innerHTML`, `eval`, `dangerouslySetInnerHTML`); confidence tiering; framework patterns (Vue `v-html`, Angular `bypassSecurityTrustHtml`); prototype-pollution → Critical | `dom_xss_scanner.py`; heuristic mirror in `pipeline/llm_analysis.py` |
| **SQL Injection** | Four families: **error-based** (DB error signatures + corroborating keywords), **union-based** (length + data-token thresholds), **boolean-blind** (TRUE/FALSE length differential), **time-based blind** (≥2 confirmations @ 6s) | `payload_tester.py::test_sqli` |
| **CSRF** | Missing anti-CSRF token in POST forms, JSON-CSRF probe, CORS `*`+credentials, SameSite gaps, login CSRF, AJAX-without-token | `csrf_scanner.py` |
| **IDOR / BOLA** | Numeric ID mutation (±1, double, rotate) → re-request as same user → **"same status, different sensitive content"** heuristic; cross-user ID leakage | `idor_scanner.py` |
| **Broken authorization** | URL role-classification (admin/teacher/student) → unauthenticated access test + **cross-role response comparison** + HTTP-method-override bypass | `authorization_scanner.py` |
| **Parameter exploitation** | Logical mutation, param removal, type confusion → differential response analysis | `api_parameter_mutator.py` |
| **Open redirect** | Inject `https://evil.com` into redirect-ish params; flag if reflected in `Location` header (`allow_redirects=False`) | `scanner.py::test_open_redirect` |
| **SSRF** | Inject `http://127.0.0.1`; flag if reflected in body/URL (reflection-only heuristic — misses blind SSRF) | `scanner.py::test_ssrf` |
| **Info leakage** | Regex for stack traces, DB errors, file paths, secrets; **timing/boolean oracles** | `response_analyzer.py` |
| **Security headers / cookies** | Passive check for missing HSTS/XFO/XCTO/CSP/Referrer-Policy; missing `HttpOnly`/`Secure` | `scanner.py::analyze_security_headers`, `analyze_cookies` |
| **Directory / file exposure** | Forced browsing against a small dir wordlist | `scanner.py::dir_bruteforce` |
| **JS endpoint disclosure** | Regex-mine `/api/`, `/v1/`, `/v2/` paths from inline + external JS | `js_endpoint_extractor.py` |
| **Hardcoded secrets / insecure transport** | Regex for `api_key`/`Bearer`/AWS `AKIA…`; `http://` URLs in client JS | `pipeline/llm_analysis.py` detectors |
| **Attack chains, stored-XSS hotspots, hidden endpoints, upload risks** | LLM reasoning over structure/JS | `gemini_analyzer.py` |

---

## 📂 Complete file-by-file reference

### Backend root — `backend/`

| File | Purpose |
|------|---------|
| **`app.py`** | Flask API + CLI entry. Routes: `POST /scan` (legacy, flattens findings into a `vulnerabilities[]` list with per-category severities + summary), `POST /scan/pipeline` (staged pipeline), `POST /scan/combined` (both engines merged), `GET /reports/<file>` (serve reports), `GET /history` (list past JSON reports), `GET /` (health). `run_cli()` prints a summary when invoked with a URL arg. |
| **`scanner.py`** | Legacy orchestrator. `scan_url()` is the master pipeline (crawl → per-page scan → dir brute → redirect/SSRF → async XSS/SQLi → authz/IDOR modules → Gemini → report). Also hosts `scan_url_pipeline()` (bridge to the pipeline) and `scan_url_combined()` (bridge to the combined engine), the BFS `crawl_links`, scope helpers (`is_same_domain` — note: naive last-two-labels logic, breaks on `co.uk`), `analyze_security_headers`, `analyze_cookies`, `test_open_redirect`, `test_ssrf`, `dir_bruteforce`, `detect_sensitive_data`, and the `scan_*_with_gemini` wrappers. |
| **`combined_scan.py`** | The combined-engine adapter. `run_combined()` runs the pipeline + legacy `scan_url()`, tags each finding's `source`/`engine`, and funnels both through `normalize → dedup → validate → reporting` into one report. `legacy_raw_findings()` flattens a legacy result dict into raw findings with a canonical `type` (aligned to the pipeline vocabulary so fingerprints collide and corroborate). Adds an `engines` breakdown to the payload. Offline-capable via `run_legacy=False` + injected `fetch`. |
| **`async_scanner.py`** | Concurrent injection engine. `run_async_scan(links)` uses `aiohttp` + `asyncio.gather` to test all URLs for XSS/SQLi in parallel. Per-URL worker extracts params or, if none, calls the **Gemini param generator** (falls back to `DEFAULT_COMMON_PARAMS`). Blocking `requests`-based detectors are offloaded via `asyncio.to_thread`. Includes UA rotation + jitter + `Semaphore(5)` as light WAF/rate-limit evasion. Feeds `xss_vulnerabilities`/`sql_vulnerabilities`. |
| **`payload_tester.py`** | **The real XSS/SQLi detection engine** (the `.txt` payload files are just reference corpora). Context-aware XSS (`CANARY`, `determine_contexts`, `is_safe_html_encoding`, `is_executable_context`, `test_xss`) and four-family SQLi (`test_sql`, `test_time_sql`, `test_error_sql`, `test_sqli`) with heavy false-positive-reduction. Exports the shared `session` + `HEADERS` used across the codebase. |
| **`form_scanner.py`** | Discovers `<form>`s, extracts `<input>/<textarea>/<select>`, and tests them **method-aware** (POST forms get POST-body injection — which the URL-only async scanner can't do). Returns per-form `{xss, sql}`. |
| **`csrf_scanner.py`** | Multi-vector CSRF: missing token, JSON-CSRF (active probe), CORS `*`+credentials (Critical), SameSite gaps, login CSRF, AJAX-without-token. |
| **`dom_xss_scanner.py`** | Static DOM-XSS taint analyzer. `SOURCES`/`SINKS`/`HIGH_CONFIDENCE_SINKS`/`AMBIGUOUS_SINKS` + `FRAMEWORK_PATTERNS`. Builds a tainted-variable map per script, matches source→sink flows (single-line + limited look-ahead), escalates prototype-pollution to Critical, suppresses lone low-confidence noise around framework markers. |
| **`response_analyzer.py`** | Differential / side-channel detection ("a vuln isn't always an error"). Response diffing (status/length/**timing >100ms**/JSON fields), `analyze_leakage` (stack traces, DB errors, file paths, secrets), boolean & time-based oracles, `detect_authentication_bypass` (Authorization-header variants). |
| **`api_parameter_mutator.py`** | Logic-based parameter fuzzing (IDOR/BOLA-adjacent). Value mutations, param removal, type confusion → flags via response differentials. Session-aware. |
| **`authorization_scanner.py`** | RBAC / broken-access-control. Classifies endpoints by role pattern, tests unauthenticated access, **cross-role access comparison**, missing-authorization, and HTTP-method-override bypass. |
| **`idor_scanner.py`** | IDOR scanner. Extracts numeric IDs (query + path), mutates them, and flags "same status + different sensitive content"; also cross-user IDOR (user A's response leaking user B's identifiers). |
| **`session_manager.py`** | Stateful multi-identity layer that makes authz/IDOR/workflow testing possible. Manages named `requests.Session`s, registers users/roles, `login()` (captures cookies + auto-extracts JWT/API tokens), and `request_with_context()` (the primitive every scanner calls; logs `request_history` for attack-chain reconstruction). |
| **`gemini_analyzer.py`** | **The AI reasoning engine.** `GeminiAnalyzer` wraps `google.genai`. Model fallback chain (`gemini-2.0-flash` → `-flash-lite` → `1.5-flash` → `1.5-pro`); `_safe_generate` enforces a 2s min interval, exponential backoff on 429/503, a class-wide 10-min rate-limit cooldown, and disables safety filters. Analysis methods: `analyze_endpoint`, `generate_smart_payloads`, `analyze_responses`, `detect_stored_xss_hotspots`, `analyze_file_upload_risks`, `detect_workflow_chains`, `identify_hidden_endpoints`, `generate_recommendations`. Each prompts for strict JSON and recovers it via regex. |
| **`gemini_param_generator.py`** | AI-assisted parameter discovery. `generate_parameters_with_gemini` (cached, context-built from form fields + JS endpoints, dynamic model listing) with `DEFAULT_COMMON_PARAMS` fallback. `generate_parameters` unions defaults + form names + URL params + AI suggestions (guaranteed superset). |
| **`report_generator.py`** | Renders findings to HTML + JSON in `reports/`. Dedicated purple "Gemini AI Analysis" block keeps AI-derived findings visually separate from deterministic ones; JSON keeps a separate `gemini_ai_findings` object. `sanitize_filename` for report names. ⚠️ Builds HTML via f-strings without output escaping. |
| **`js_endpoint_extractor.py`** | Legacy JS endpoint miner (`/api/`, `/v1/`, `/v2/` from inline + external scripts). |
| **`payloads/xss_payloads.txt`** | Four canonical reflected-XSS vectors (reference corpus; runtime uses `ADVANCED_XSS_PAYLOADS` in code). |
| **`payloads/sql_payloads.txt`** | Five classic SQLi strings (reference corpus; runtime uses the richer in-code sets). |

### Pipeline — `backend/pipeline/`

| File | Purpose |
|------|---------|
| **`__init__.py`** | Package surface. Exports `Pipeline`, `PipelineConfig`, `run_pipeline`, and models. |
| **`orchestrator.py`** | `Pipeline` class — chains all 11 stages; injects `fetch` and `gemini`; tracks `stages_run`. `run_pipeline()` convenience entry. |
| **`models.py`** | Shared dataclasses `Endpoint`, `JSAsset`, `Chunk`, `Finding` + `SEVERITY_ORDER`. `Finding.compute_fingerprint()` = SHA1 of `type|normalized_url|parameter` (dedup identity). |
| **`config.py`** | `PipelineConfig` dataclass + `from_env()` reading `DSG_*` env vars. |
| **`crawler.py`** | Stage 1 — injected-fetch BFS crawl, same-domain, `max_depth`/`max_links` bounded. |
| **`endpoint_discovery.py`** | Stage 2 — merge crawled URLs + JS paths into unique `Endpoint`s; `API_PATTERNS`. |
| **`js_extraction.py`** | Stage 3 — collect external (deduped) + inline scripts; `mine_endpoints`. |
| **`unminify.py`** | Stage 4 — beautify + webpack unbundle; conservative regex fallback if `jsbeautifier` absent. |
| **`chunking.py`** | Stage 5 — overlapping windows over JS/HTML/endpoints; overlap preserves cross-boundary context. |
| **`rag.py`** | Stage 6 — `TfidfRetriever` (fit/query/retrieve); smoothed IDF; cosine similarity; pure Python. |
| **`llm_analysis.py`** | Stage 7 — `DETECTORS` catalog (DOM XSS, Hardcoded Secret, Insecure Transport, Potential IDOR); Gemini path + heuristic fallback/safety-net; tags source `gemini-rag`/`heuristic-rag`. |
| **`normalization.py`** | Stage 8 — coerce heterogeneous dicts → canonical `Finding`; severity aliasing. |
| **`dedup.py`** | Stage 9 — fingerprint merge; keep strongest severity/confidence; corroboration bump. |
| **`validation.py`** | Stage 10 — structural gate + optional low-confidence drop; returns `(accepted, rejected)`. |
| **`reporting.py`** | Stage 11 — build payload; write `findings.json`; best-effort legacy HTML/JSON. |

### Frontend — `frontend/` (Next.js 14, App Router)

| File | Purpose |
|------|---------|
| **`app/page.tsx`** | Single-page client UI. Three tabs (Scanner / History / Reports). `startScan()` POSTs to the backend and flattens categorized findings into severity-colored cards. History persists in `localStorage`. ⚠️ On fetch failure it injects **three hardcoded demo vulnerabilities** and marks the scan "completed" — a UX caveat. |
| **`app/layout.tsx`** | Root layout + metadata. |
| **`app/globals.css`** | Global styles / CSS variables consumed by Tailwind. |
| **`app/api/scan/route.ts`** | Server-side proxy route to the backend (`POST` forwards, `GET` health). Currently **unused** — the page calls `localhost:5000` directly. |
| **`lib/utils.ts`** | `cn()` = `twMerge(clsx(...))` class-merge helper. |
| **`components/ui/`** | Empty — no extracted component library yet (UI is monolithic in `page.tsx`). |
| **`package.json` / `tailwind.config.js` / `next.config.js` / `tsconfig.json`** | Next 14.2.3, React 18, Tailwind 3.4, `lucide-react`, `clsx`, `tailwind-merge`. |

### Tests — `backend/tests/`
One suite per pipeline stage, an end-to-end orchestrator test, and a combined-engine
suite. Fully offline & deterministic via `conftest.py`:
- **Injected fetcher**: an in-memory `SITE` dict maps URLs → `(status, ct, body)`,
  seeded with one of each detectable issue (DOM sink, hardcoded key, `http://`
  URL, IDOR-shaped endpoints).
- **Fake LLM** (`FakeGemini`): implements `is_available`/`is_rate_limited`/
  `analyze_endpoint` with canned output; tests also pass `gemini=None` or a
  `Down` stub to exercise the fallback path.
- Suites: `test_orchestrator` (stage order + e2e), `test_rag` (retrieval ranking),
  `test_validation`, `test_llm_analysis` (gemini vs heuristic source tagging),
  `test_combined` (both-engine merge + **cross-engine corroboration** raising
  confidence), `test_crawler`, `test_endpoint_discovery`, `test_js_extraction`,
  `test_unminify`, `test_chunking`, `test_dedup`, `test_normalization`, `test_reporting`.

### Infra & config

| File | Purpose |
|------|---------|
| **`.github/workflows/ci.yml`** | CI/CD. **backend**: flake8 (hard-fail on `E9,F63,F7,F82` only) + `pytest --cov` across Python 3.10/3.11/3.12 with `DSG_USE_LLM=0`. **frontend**: `npm ci` → lint → `next build`. **deploy** (main push only): builds the backend Docker image, then a placeholder deploy step. Concurrency group cancels superseded runs. |
| **`backend/Dockerfile`** | `python:3.12-slim`; installs `requirements.txt` + gunicorn; runs `gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 600 app:app` (long timeout for slow scans). |
| **`backend/.dockerignore`** | Excludes `venv/`, `__pycache__`, `reports/`, `*.log`, `tests/`, `.env` (keeps secrets/artifacts out of the image). |
| **`backend/pytest.ini`** | `testpaths=tests`, quiet mode. |
| **`backend/requirements.txt`** | Runtime: `flask`, `requests`, `beautifulsoup4`, `aiohttp`, `google-genai`, `urllib3`, `python-dotenv`. |
| **`backend/requirements-dev.txt`** | Adds `pytest`, `pytest-cov`, `flake8`, `jsbeautifier`. |
| **`backend/.env`** | Holds `GEMINI_API_KEY`, proxy vars, OAuth IDs/secrets (not committed values). Loaded via `python-dotenv`. |
| **`backend/reports/`** | Output directory for generated HTML/JSON reports + `findings.json` (auto-created at runtime; starts empty). |
| **`ARCHITECTURE.md`** (repo root) | The companion doc — diagrams of both engines, the pipeline, and the AI data-flow. |

---

## ⚙️ Install & run

```bash
# 1. venv
python3 -m venv venv && source venv/bin/activate

# 2. deps
pip install -U pip setuptools wheel
pip install -r backend/requirements.txt

# 3. (optional) Gemini key — omit to run fully offline
echo "GEMINI_API_KEY=your_key_here" >> backend/.env

# 4a. CLI scan (legacy engine)
python backend/app.py https://demo.testfire.net

# 4b. API server + pipeline endpoint
python backend/app.py
curl -X POST localhost:5000/scan/pipeline \
     -H 'Content-Type: application/json' \
     -d '{"url":"https://demo.testfire.net"}'
```

Frontend:
```bash
cd frontend && npm install && npm run dev   # http://localhost:3000
```

**Only scan targets you own or have explicit permission to test.**

---

## 🔧 Configuration

All pipeline knobs are env-overridable (`PipelineConfig.from_env`):

| Var | Default | Meaning |
|-----|---------|---------|
| `DSG_MAX_DEPTH` | 2 | Crawl depth |
| `DSG_MAX_LINKS` | 50 | Max pages crawled |
| `DSG_SAME_DOMAIN` | 1 | Restrict to start domain |
| `DSG_TIMEOUT` | 10 | Per-request timeout (s) |
| `DSG_CHUNK_SIZE` | 1200 | Chunk size (chars) |
| `DSG_CHUNK_OVERLAP` | 150 | Chunk overlap (chars) |
| `DSG_TOP_K` | 6 | RAG retrieval depth |
| `DSG_USE_LLM` | 1 | Use Gemini when available (0 = force offline) |
| `DSG_DROP_LOW_CONFIDENCE` | 0 | Drop low-confidence findings |

Plus `GEMINI_API_KEY` for the LLM layer.

---

## ✅ Testing

```bash
cd backend
pip install -r requirements-dev.txt
pytest --cov=pipeline --cov-report=term-missing
```

The pipeline suite is fully offline (injected fetch + fake LLM) and deterministic
— no network, no API key. This is what CI runs.

---

## 🔄 CI/CD & Docker

CI (`.github/workflows/ci.yml`) runs on every push/PR to `main`: backend
lint+test matrix (3.10/3.11/3.12, `DSG_USE_LLM=0`), frontend lint+build, and a
main-only Docker build + placeholder deploy.

```bash
docker build -t dsg-suite-backend backend
docker run -p 5000:5000 --env-file backend/.env dsg-suite-backend
```

---

## ⚠️ Limitations & known gaps

Being able to critique your own tool is a strong interview signal. The real ones:

**Detection accuracy**
- **SSRF/open-redirect are reflection-only** — they detect the payload bouncing
  back, not an actual server-side outbound request. Blind SSRF is missed; simple
  echoes false-positive. No OOB/callback canary.
- **DOM-XSS is regex/line-oriented, not AST/data-flow** — misses multi-line and
  cross-function flows, false-positives on sink names in strings/comments, and is
  unaware of sanitizers (DOMPurify won't clear a finding). Only inline scripts are
  body-analyzed here.
- **SQLi error-based** needs verbose DB errors (fails on generic 500s); union/
  boolean rely on response-length heuristics that dynamic pages defeat.
- **CSRF token detection is pattern-based** — custom or header-based (double-submit)
  tokens read as vulnerable (false positives). The JSON-CSRF check sends a **real
  state-changing POST**.

**Scope / robustness**
- **Root-domain logic is TLD-naive** (`[-2:]`) — breaks on `co.uk`, treats all
  subdomains as in-scope.
- **Coverage caps**: legacy `MAX_DEPTH=3`/`MAX_LINKS=100`; a global 300s async
  budget can truncate large-site results.
- **Duplication/drift**: subdomain + directory logic exist both as modules and as
  inline copies in `scanner.py`; the inline copies are the ones that run. The two
  Gemini integrations use different model lists and logging styles.
- **Naive param parsing** in the async scanner (`split("?")`/`split("=")` instead
  of `parse_qsl`).

**AI-specific**
- **LLM output is trusted as attack input** (`generate_parameters` → HTTP requests)
  without validation — a prompt-injection surface.
- **Safety filters are disabled** (`BLOCK_NONE`) for offensive context.
- **Non-deterministic findings** (`temperature=0.7`); heavy dependence on the live
  Gemini service and its rate limits for the legacy engine's AI findings.
- **`report_generator.py` doesn't escape HTML** — self-XSS-able report.

**Frontend**
- Page calls `localhost:5000` directly (CORS-dependent), bypassing its own proxy.
- On backend failure it **fabricates demo vulnerabilities** and shows them as real.

---

## 🎤 Interview crib sheet

One-paragraph pitch:
> *DSG_Suite is a web vulnerability scanner with two engines: a classical
> deterministic scanner and a staged, dependency-injected RAG pipeline. The
> pipeline crawls a site, extracts and unminifies JavaScript, chunks it with
> overlap, retrieves the most relevant chunks per vulnerability class using a
> pure-Python TF-IDF cosine retriever, and hands them to Google Gemini for
> reasoning — or to deterministic regex detectors when the LLM is unavailable.
> Heterogeneous findings are normalized to one schema, deduplicated by
> fingerprint with corroboration-based confidence, and passed through a validation
> gate before reporting. AI augments but never gates the scan, and the whole
> pipeline runs offline in CI with an injected fetcher and a fake LLM.*

Six things to be ready to defend:
1. **Why RAG here?** Minified bundles are too big for a prompt; retrieval keeps
   prompts small, focused, cheap, and lowers hallucination surface.
2. **Why pure-Python TF-IDF instead of embeddings?** Deterministic, no external
   service, CI-friendly, zero heavy deps. Trade-off: no semantic similarity.
3. **How is untrusted LLM output handled?** Regex JSON extraction → schema
   coercion → validation gate that keeps rejects with reasons → source tagging.
4. **How are false positives reduced?** Canary + context + encoding + executable-
   context + baseline-length checks for XSS; multi-confirmation thresholds for
   SQLi; corroboration bump on dedup; LLM `confidence` self-rating.
5. **What are the AI risks?** Trusting model output as attack input (prompt
   injection), disabled safety filters, non-determinism, unescaped report output.
6. **How do the two engines combine?** `combined_scan.run_combined` funnels both
   engines' findings through the shared `normalize → dedup → validate → report`
   backbone; a shared `type|url|param` fingerprint lets an active-confirmed
   finding and an LLM-reasoned one **merge and boost each other's confidence** —
   passive triage + active confirmation, scored by cross-engine consensus.

---

## 📚 Glossary

- **RAG** — Retrieval-Augmented Generation: retrieve relevant context, then have
  the LLM reason over only that context.
- **TF-IDF** — Term Frequency × Inverse Document Frequency: classic weighting that
  scores how important a term is to a document relative to the corpus.
- **Cosine similarity** — angle-based similarity between two sparse term vectors.
- **Taint analysis (source→sink)** — tracking user-controlled input (source) to a
  dangerous operation (sink); the basis of DOM-XSS detection.
- **IDOR / BOLA** — Insecure Direct Object Reference / Broken Object-Level
  Authorization: accessing another user's object by changing an ID.
- **Canary** — a benign unique marker injected first to learn *where* input
  reflects before firing a real payload.
- **Differential analysis** — inferring a vulnerability from *differences* in
  status/length/timing/content between requests, not from an error message.
- **Fingerprint** — a stable hash (here `type|url|param`) that identifies "the same
  finding" for deduplication.
- **Graceful degradation** — the system keeps working (offline heuristics) when a
  dependency (the LLM) is unavailable.

---

## 🔐 Legal & ethical disclaimer

This tool is for **educational purposes only**. Scan only your own applications,
localhost, or intentionally vulnerable targets (DVWA, WebGoat, `demo.testfire.net`).
**Do NOT scan systems you do not own or lack explicit written permission to test.**
Unauthorized scanning is illegal in most jurisdictions.
