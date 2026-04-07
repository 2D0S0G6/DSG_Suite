# 🚀 DSG_Suite

This document contains the README for the **Web Application Vulnerability Scanner** project and the technical walkthrough for **Cyber Forensics Lab 4 (FAT32 Analysis)** on Ubuntu.

---

## 🛡️ Web Application Vulnerability Scanner

A Python-based automated tool to scan web applications for common security vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), CSRF misconfigurations, open directories, and security header issues. This project is built for learning and demonstration purposes on intentionally vulnerable applications.

### 📌 Features
* **Crawl** target website and collect internal links.
* **Detect**:
    * SQL Injection vulnerabilities, including error-based, boolean-based, and time-based checks.
    * Cross-Site Scripting (XSS), including reflected and DOM XSS sink discovery.
    * Missing CSRF protection on POST forms.
    * Open redirect and SSRF risk indicators on query parameters.
    * Directory and file exposure.
    * Weak or missing HTTP security headers and cookie hardening issues.
    * JavaScript API endpoints discovered from inline and external scripts.
* **Generate scan reports** in Console, JSON, or HTML format.
* **Modular design** for easy extension.

### 🧰 Tech Stack
* **Language**: Python 3
* **Libraries**: `requests`, `beautifulsoup4`, `argparse`, `json`, `socket`
* **Optional**: `flask` (web UI), `nmap` (port scanning)

### ⚠️ Legal & Ethical Disclaimer
This tool is for educational purposes only. Scan only your own applications, localhost, or platforms like DVWA/WebGoat. **Do NOT scan real websites without permission.**

### 🗂️ Project Structure
```text
backend/
│
├── app.py               # Main entry point (web API)
├── scanner.py           # CLI scan orchestration
├── async_scanner.py     # Async scan worker
├── form_scanner.py
├── csrf_scanner.py
├── dom_xss_scanner.py
├── subdomain_scanner.py
├── js_endpoint_extractor.py
├── report_generator.py
├── gemini_param_generator.py  # Gemini parameter inferrer
├── payload_tester.py
├── requirements.txt
├── .env
└── reports/
```

## ⚙️ Install and run

1. Create and activate venv:

```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:

```bash
pip install -U pip setuptools wheel
pip install -r requirements.txt
```

3. Set Gemini API key in `backend/.env`:

```ini
GEMINI_API_KEY=your_gemini_api_key_here
HTTP_PROXY=
HTTPS_PROXY=
```

4. Run scan:

```bash
python backend/app.py https://demo.testfire.net
```

5. For real websites, only scan targets you own or have explicit permission to test. The scanner now analyzes internal pages, forms, JS endpoints, redirects, SSRF patterns, and security headers.

## 🔐 Gemini config note

- Current implementation uses `google-generativeai` client.
- If you have a newer supported package, update `gemini_param_generator.py` to the matching API and replace `google-generativeai` in `requirements.txt`.
- For debugging, scan will fallback to default parameters when key or model not available.

🚀 Installation & UsageBash# Clone and setup
git clone [https://github.com/yourusername/vuln-scanner.git](https://github.com/yourusername/vuln-scanner.git)
cd vuln-scanner
pip install -r requirements.txt

# Run scans
python scanner.py http://localhost/dvwa
python scanner.py [http://targetsite.com](http://targetsite.com) --sql --xss
