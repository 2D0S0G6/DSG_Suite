# DSG_Suite — Web Application Vulnerability Scanner

A Python-based automated scanner that crawls a target web application and checks it for common security weaknesses, with optional Google Gemini assistance for smarter parameter discovery.

## Overview

DSG_Suite is a modular web security scanner built around a small Flask app that also runs as a command-line tool. It crawls internal links, discovers forms and JavaScript endpoints, and runs a set of focused checks (SQL injection, XSS, CSRF, IDOR/authorization, and more) before producing a consolidated report. It is intended for learning and for testing applications you own or are explicitly authorised to assess.

## Features

- Crawls a target site and collects internal links (bounded by depth and link limits).
- SQL injection checks (error-based, boolean-based, and time-based).
- Cross-Site Scripting detection, including reflected checks and DOM XSS sink discovery.
- Form and CSRF-protection scanning on POST forms.
- IDOR and authorization testing with session handling and API parameter mutation.
- JavaScript endpoint extraction from inline and external scripts.
- Subdomain and directory/file exposure discovery.
- Response analysis and HTTP security-header/cookie hardening review.
- Optional Google Gemini integration to infer likely parameters and help analyse responses (falls back to defaults when no API key is configured).
- Report generation in console, JSON, and HTML formats.

## Tech stack

- **Language:** Python 3
- **Web/API:** Flask
- **HTTP & parsing:** `requests`, `aiohttp`, `beautifulsoup4`, `urllib3`
- **AI (optional):** `google-genai` (Google Gemini)
- **Config:** `python-dotenv`

## Getting started

```bash
# 1. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. (Optional) configure Gemini in backend/.env
#    GEMINI_API_KEY=your_api_key_here

# 4a. Run a scan from the command line
python backend/app.py https://demo.testfire.net

# 4b. Or start the Flask API (no target argument)
python backend/app.py
# then POST JSON {"url": "https://target"} to http://127.0.0.1:5000/scan
```

The CLI prints a summary and writes an HTML report to `backend/reports/`.

> **Legal note:** Use only against applications you own or have explicit permission to test (e.g. localhost, DVWA, WebGoat, or intentionally vulnerable demo sites). Do not scan third-party systems without authorisation.

## Project structure

```text
backend/
├── app.py                     # Flask API + CLI entry point
├── scanner.py                 # Scan orchestration and crawler
├── async_scanner.py           # Async scan worker
├── form_scanner.py            # Form discovery and testing
├── csrf_scanner.py            # CSRF protection checks
├── dom_xss_scanner.py         # DOM XSS sink discovery
├── idor_scanner.py            # IDOR checks
├── authorization_scanner.py   # Authorization testing
├── api_parameter_mutator.py   # API parameter mutation
├── session_manager.py         # Authenticated session handling
├── response_analyzer.py       # Response inspection
├── js_endpoint_extractor.py   # JS endpoint discovery
├── subdomain_scanner.py       # Subdomain enumeration
├── payload_tester.py          # Shared HTTP session and payload testing
├── gemini_analyzer.py         # Gemini-assisted analysis
├── gemini_param_generator.py  # Gemini-assisted parameter inference
├── report_generator.py        # Console / JSON / HTML reporting
├── dir_wordlist.py            # Directory wordlist
├── param_wordlist.py          # Parameter wordlist
├── payloads/                  # SQLi and XSS payload lists
├── requirements.txt
└── *.md / *.txt               # Additional design and upgrade notes
```
