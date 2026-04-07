import asyncio
import json
import logging
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from async_scanner import run_async_scan
from csrf_scanner import scan_csrf
from dom_xss_scanner import scan_dom_xss
from form_scanner import scan_forms
from js_endpoint_extractor import extract_js_endpoints
from payload_tester import HEADERS, session
from report_generator import generate_html_report, generate_json_report

# 🔥 NEW: Advanced authorization & workflow testing
from session_manager import SessionManager
from idor_scanner import IDORScanner
from authorization_scanner import AuthorizationScanner
from api_parameter_mutator import APIParameterMutator
from response_analyzer import ResponseAnalyzer

# 🤖 NEW: Gemini AI Integration
from gemini_analyzer import GeminiAnalyzer

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(filename="scanner.log", level=logging.INFO)

# Limits for crawler
MAX_DEPTH = 3
MAX_LINKS = 100  # Increased for real-world coverage

COMMON_DIRS = ["admin", "dashboard", "backup", "config"]

PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
# -----------------------------
# Crawl
# -----------------------------
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_links(start_url):

    visited = set()
    to_visit = [(start_url, 0)]
    links = set()

    while to_visit:

        url, depth = to_visit.pop(0)

        if depth > MAX_DEPTH:
            continue

        if url in visited:
            continue

        visited.add(url)

        print("[DEBUG] Crawling:", url)

        try:
            response = session.get(
                url,
                headers=HEADERS,
                timeout=10
            )

            # 🔥 Fix: skip bad responses
            if response.status_code != 200:
                continue

            if "text/html" not in response.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all("a", href=True):

                href = tag.get("href")

                if not href:
                    continue

                # skip junk
                if href.startswith(("#", "mailto:", "javascript:")):
                    continue

                full_url = urljoin(url, href)

                if not full_url.startswith("http"):
                    continue

                if not is_same_domain(start_url, full_url):
                    continue

                # 🔥 normalize (avoid duplicates)
                full_url = full_url.split("#")[0]

                if full_url not in visited:
                    links.add(full_url)
                    to_visit.append((full_url, depth + 1))

                if len(links) >= MAX_LINKS:
                    return list(links)

        except Exception as e:
            print("[!] Crawl error:", url, str(e))

    return list(links)


def is_same_domain(url1, url2):
    try:
        return urlparse(url1).netloc == urlparse(url2).netloc
    except:
        return False


# -----------------------------
# URL and header helpers
# -----------------------------

def normalize_url_query(url, param, payload):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params, doseq=True), parsed.fragment))


def extract_query_parameters(url):
    if "?" not in url:
        return []

    parsed = urlparse(url)
    params = []

    for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if key and key not in params:
            params.append(key)

    return params

def analyze_security_headers(headers):
    issues = []

    expected = {
        "strict-transport-security": "Strict-Transport-Security",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "content-security-policy": "Content-Security-Policy",
        "referrer-policy": "Referrer-Policy"
    }

    for lower_name, header_name in expected.items():
        if header_name not in headers:
            issues.append(f"Missing {header_name}")

    return issues


def test_open_redirect(url):
    payload = "https://evil.com"
    open_redirect_params = ["redirect", "url", "next", "return", "dest", "destination", "rurl"]
    results = []
    params = extract_query_parameters(url)

    for param in params:
        if param.lower() not in open_redirect_params and not param.lower().endswith("url"):
            continue

        test_url = normalize_url_query(url, param, payload)

        try:
            r = requests.get(test_url, allow_redirects=False, timeout=8, verify=False)
            location = r.headers.get("Location", "")

            if payload in location:
                results.append({
                    "type": "Open Redirect",
                    "url": test_url,
                    "parameter": param,
                    "evidence": location,
                    "severity": "High",
                    "explanation": "The application reflects a redirect destination directly from a query parameter without validation.",
                    "remediation": "Validate redirect destinations against an allow-list or use relative paths only."
                })

        except Exception:
            pass

    return results


def test_ssrf(url):
    payload = "http://127.0.0.1"
    ssrf_params = ["url", "uri", "path", "endpoint", "target", "redirect"]
    results = []
    params = extract_query_parameters(url)

    for param in params:
        if param.lower() not in ssrf_params and not param.lower().endswith("url"):
            continue

        test_url = normalize_url_query(url, param, payload)

        try:
            r = requests.get(test_url, timeout=10, verify=False)

            if payload in r.text or payload in r.url:
                results.append({
                    "type": "SSRF",
                    "url": test_url,
                    "parameter": param,
                    "evidence": "Localhost URL reflected or requested",
                    "severity": "High",
                    "explanation": "A parameter appears to accept arbitrary URLs and may allow server-side request forgery.",
                    "remediation": "Validate URL input and restrict outbound requests to known safe domains."
                })

        except Exception:
            pass

    return results

# -----------------------------
# Directory brute force
# -----------------------------
def dir_bruteforce(base):

    found = []

    base_url = urlparse(base).scheme + '://' + urlparse(base).netloc

    for d in COMMON_DIRS:

        url = f"{base_url}/{d}"

        try:
            r = requests.get(url, timeout=3, verify=False)

            if r.status_code == 200:
                print("[+] Directory found:", url)
                found.append(url)

        except:
            pass

    return found


# -----------------------------
# DOM XSS detection
# -----------------------------

# -----------------------------
# Page scanning helpers
# -----------------------------

def fetch_page(url):
    try:
        return session.get(url, headers=HEADERS, timeout=10)
    except Exception as e:
        print("[!] Page fetch error:", url, str(e))
        return None


def scan_page(url):
    page_data = {
        "forms": [],
        "csrf": [],
        "dom_xss": [],
        "js_endpoints": [],
        "security_headers": [],
        "cookie_issues": []
    }

    response = fetch_page(url)
    if not response or response.status_code != 200:
        return page_data

    if "text/html" not in response.headers.get("Content-Type", ""):
        return page_data

    page_data["forms"] = scan_forms(url)
    page_data["csrf"] = scan_csrf(url)
    page_data["dom_xss"] = scan_dom_xss(url)
    page_data["js_endpoints"] = extract_js_endpoints(url)
    page_data["security_headers"] = analyze_security_headers(response.headers)
    page_data["cookie_issues"] = analyze_cookies(response.headers)

    return page_data


# =====================================================
# 🔥 NEW: AUTHORIZATION & ACCESS CONTROL TESTING
# =====================================================

def scan_idor_vulnerabilities(links, session_manager=None, session_name=None):
    """
    Test for IDOR (Insecure Direct Object Reference) vulnerabilities.
    
    Looks for sequential IDs and tests parameter mutation.
    """
    print("\n[*] Scanning for IDOR vulnerabilities...")
    findings = []
    
    idor_scanner = IDORScanner(session_manager)
    
    # Filter for API endpoints
    api_endpoints = [url for url in links if "/api/" in url or "/v1/" in url]
    
    if not api_endpoints:
        print("[!] No API endpoints to test for IDOR")
        return findings
    
    print(f"[*] Testing {len(api_endpoints)} potential API endpoints")
    
    for endpoint in api_endpoints[:10]:  # Test first 10 API endpoints
        try:
            results = idor_scanner.test_idor(endpoint, session_name)
            findings.extend(results)
        except Exception as e:
            logging.error(f"[!] IDOR test error on {endpoint}: {e}")
    
    print(f"[+] IDOR scan complete: {len(findings)} potential vulns found")
    return findings


def scan_authorization_flaws(links, session_manager=None, user_sessions=None):
    """
    Test for broken authorization (RBAC bypass, privilege escalation).
    
    Attempts:
    - Unauthenticated access to protected endpoints
    - Cross-role access testing
    """
    print("\n[*] Scanning for authorization flaws...")
    findings = []
    
    auth_scanner = AuthorizationScanner(session_manager)
    
    # Identify role-based endpoints
    categorized = auth_scanner.identify_endpoints(links)
    
    print(f"[*] Found {len(categorized['admin'])} admin endpoints")
    print(f"[*] Found {len(categorized['teacher'])} teacher endpoints")
    
    # Test unauthenticated access
    for endpoint in categorized['admin'] + categorized['teacher']:
        try:
            is_accessible, status, _ = auth_scanner.test_unauthenticated_access(endpoint)
            if is_accessible:
                findings.append({
                    "type": "Unauthenticated Access to Protected Endpoint",
                    "severity": "Critical",
                    "endpoint": endpoint,
                    "status_code": status,
                    "evidence": f"Protected endpoint returned {status} without authentication",
                    "remediation": "Require authentication and proper authorization for all protected endpoints."
                })
        except Exception as e:
            logging.error(f"[!] Auth test error on {endpoint}: {e}")
    
    # Test cross-role access if we have sessions
    if user_sessions and session_manager:
        for endpoint in categorized['admin']:
            try:
                cross_findings = auth_scanner.test_cross_role_access(endpoint, user_sessions)
                findings.extend(cross_findings)
            except:
                pass
    
    print(f"[+] Authorization scan complete: {len(findings)} potential vulns found")
    return findings


def scan_api_parameters(links, session_manager=None, session_name=None):
    """
    Scan API endpoints for parameter-based vulnerabilities.
    
    Tests:
    - Parameter mutation (ID tampering)
    - Parameter removal
    - Type confusion
    """
    print("\n[*] Scanning API parameters for exploitation...")
    findings = []
    
    mutator = APIParameterMutator(session_manager)
    
    # Filter API endpoints
    api_endpoints = [url for url in links if "/api/" in url and "?" in url]
    
    if not api_endpoints:
        print("[!] No API endpoints with parameters to test")
        return findings
    
    print(f"[*] Testing parameters in {len(api_endpoints)} API endpoints")
    
    for endpoint in api_endpoints[:10]:  # Test first 10
        try:
            param_findings = mutator.scan_api_parameters([endpoint], session_name)
            findings.extend(param_findings)
        except Exception as e:
            logging.error(f"[!] Parameter scan error on {endpoint}: {e}")
    
    print(f"[+] Parameter scan complete: {len(findings)} potential vulns found")
    return findings


def scan_response_anomalies(links):
    """
    Analyze responses for information leakage and subtle vulnerabilities.
    
    Detects:
    - Stack traces
    - Database errors
    - Secrets in responses
    - Authentication bypass indicators
    """
    print("\n[*] Scanning responses for information leakage...")
    findings = []
    
    analyzer = ResponseAnalyzer()
    
    for url in links[:20]:  # Sample first 20 URLs
        try:
            resp = requests.get(url, verify=False, timeout=10)
            
            # Analyze for leakage
            leakage = analyzer.analyze_leakage(resp)
            findings.extend(leakage)
            
            # Detect auth bypass indicators
            auth_bypass = analyzer.detect_authentication_bypass(url, [])
            findings.extend(auth_bypass)
            
        except:
            pass
    
    print(f"[+] Response analysis complete: {len(findings)} potential issues found")
    return findings


# =====================================================
# 🤖 NEW: GEMINI AI-POWERED SCANNING
# =====================================================

def scan_with_gemini_endpoint_analysis(links, api_key: str = None) -> list:
    """
    Use Gemini AI to intelligently analyze endpoints.
    
    Identifies IDOR, auth issues, and attack vectors using AI analysis.
    """
    print("\n[*] Running Gemini AI endpoint analysis...")
    findings = []
    
    gemini = GeminiAnalyzer(api_key)
    
    if not gemini.is_available():
        print("[!] Gemini not available (set GEMINI_API_KEY)")
        return findings
    
    # Filter API endpoints for analysis
    api_endpoints = [url for url in links if "/api/" in url]
    
    if not api_endpoints:
        return findings
    
    print(f"[*] Analyzing {len(api_endpoints)} endpoints with Gemini AI...")
    
    for endpoint in api_endpoints[:15]:  # Analyze first 15
        try:
            # Get sample response
            try:
                resp = requests.get(endpoint, verify=False, timeout=5)
                response_sample = resp.text[:500]
            except:
                response_sample = None
            
            # Extract parameters from URL
            parsed = urlparse(endpoint)
            params = [k for k, v in parse_qsl(parsed.query)]
            
            # Analyze with Gemini
            analysis = gemini.analyze_endpoint(
                endpoint=endpoint,
                method="GET",
                parameters=params,
                response_sample=response_sample
            )
            
            if "potential_vulnerabilities" in analysis:
                for vuln in analysis.get("potential_vulnerabilities", []):
                    findings.append({
                        "type": f"Gemini AI: {vuln}",
                        "endpoint": endpoint,
                        "ai_analysis": analysis.get("endpoint_purpose", ""),
                        "suggested_tests": analysis.get("suggested_tests", []),
                        "risk_level": analysis.get("risk_level", "medium"),
                        "source": "Gemini AI Analysis"
                    })
            
            logging.info(f"[+] Analyzed {endpoint}")
        
        except Exception as e:
            logging.error(f"[!] Gemini analysis error: {e}")
    
    print(f"[+] Gemini endpoint analysis complete: {len(findings)} findings")
    return findings


def scan_stored_xss_with_gemini(forms: list, links: list, api_key: str = None) -> list:
    """
    Use Gemini to detect stored XSS by analyzing form-to-display patterns.
    """
    print("\n[*] Running Gemini stored XSS detection...")
    findings = []
    
    if not forms:
        return findings
    
    gemini = GeminiAnalyzer(api_key)
    
    if not gemini.is_available():
        return findings
    
    # Prepare page data
    pages_data = [{"path": url} for url in links[:10]]
    
    # Analyze with Gemini
    hotspots = gemini.detect_stored_xss_hotspots(forms, pages_data)
    
    for hotspot in hotspots:
        findings.append({
            "type": "Potential Stored XSS Hotspot",
            "form_field": hotspot.get("form_field", "unknown"),
            "likely_reflection": hotspot.get("likely_reflection", "unknown"),
            "attack_chain": hotspot.get("attack_chain", ""),
            "risk_level": hotspot.get("risk", "medium"),
            "evidence": f"Form input '{hotspot.get('form_field')}' may appear in {hotspot.get('likely_reflection')}",
            "severity": "High" if hotspot.get("risk") == "high" else "Medium"
        })
    
    print(f"[+] Found {len(findings)} stored XSS hotspots")
    return findings


def scan_file_uploads_with_gemini(links: list, api_key: str = None) -> list:
    """
    Use Gemini to analyze file upload endpoints.
    """
    print("\n[*] Running Gemini file upload analysis...")
    findings = []
    
    gemini = GeminiAnalyzer(api_key)
    
    if not gemini.is_available():
        return findings
    
    # Find potential upload endpoints
    upload_keywords = ["upload", "file", "attachment", "avatar", "profile", "document"]
    upload_endpoints = [url for url in links if any(kw in url.lower() for kw in upload_keywords)]
    
    if not upload_endpoints:
        print("[!] No file upload endpoints found")
        return findings
    
    print(f"[*] Analyzing {len(upload_endpoints)} upload endpoints with Gemini...")
    
    # Analyze with Gemini
    analyses = gemini.analyze_file_upload_risks(upload_endpoints[:10])
    
    for analysis in analyses:
        # Check if files might be accessible
        endpoint = analysis.get("endpoint", "")
        vulnerabilities = analysis.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            findings.append({
                "type": "File Upload Vulnerability",
                "endpoint": endpoint,
                "vulnerability": vuln,
                "bypass_techniques": analysis.get("bypass_techniques", []),
                "storage_path": analysis.get("storage_path", "unknown"),
                "exploit_chain": analysis.get("exploit_chain", ""),
                "severity": "High"
            })
    
    print(f"[+] File upload analysis complete: {len(findings)} findings")
    return findings


def detect_workflow_chains_with_gemini(links: list, all_apis: list, 
                                       api_key: str = None) -> list:
    """
    Use Gemini to detect multi-step attack chains.
    """
    print("\n[*] Running Gemini workflow chain detection...")
    findings = []
    
    gemini = GeminiAnalyzer(api_key)
    
    if not gemini.is_available():
        return findings
    
    # Detect chains
    chains = gemini.detect_workflow_chains(links, all_apis)
    
    for chain in chains:
        findings.append({
            "type": "Multi-Step Attack Chain",
            "name": chain.get("name", "unknown"),
            "steps": chain.get("steps", []),
            "entry_point": chain.get("entry_point", ""),
            "exploitation_point": chain.get("exploitation_point", ""),
            "vulnerabilities": chain.get("vulnerability_types", []),
            "impact": chain.get("impact", "medium"),
            "poc": chain.get("proof_of_concept", ""),
            "severity": "Critical" if chain.get("impact") == "high" else "High"
        })
    
    print(f"[+] Detected {len(findings)} attack chains")
    return findings


def identify_hidden_endpoints_with_gemini(all_js_content: list, 
                                          api_key: str = None) -> list:
    """
    Use Gemini to identify hidden/forgotten endpoints from JavaScript.
    """
    print("\n[*] Running Gemini hidden endpoint detection...")
    findings = []
    
    gemini = GeminiAnalyzer(api_key)
    
    if not gemini.is_available():
        return findings
    
    if not all_js_content:
        print("[!] No JavaScript content to analyze")
        return findings
    
    # Identify hidden endpoints
    endpoints = gemini.identify_hidden_endpoints(all_js_content)
    
    for endpoint_info in endpoints:
        findings.append({
            "type": f"Hidden/Debug Endpoint - {endpoint_info.get('type', 'unknown')}",
            "endpoint": endpoint_info.get("endpoint", ""),
            "purpose": endpoint_info.get("likely_purpose", ""),
            "auth_required": endpoint_info.get("authentication", "unknown"),
            "exposure_risk": endpoint_info.get("exposure_risk", "medium"),
            "severity": "Critical" if endpoint_info.get("exposure_risk") == "high" else "High"
        })
    
    print(f"[+] Identified {len(findings)} hidden endpoints")
    return findings


# =====================================================
# MAIN SCANNER FUNCTION
# =====================================================

def scan_url(url):
    print("[+] Discovering subdomains")
    subs = find_subdomains(url)

    print("\n[+] Crawling site")
    links = crawl_links(url)

    pages = [url] + [link for link in links if link != url]
    print("[+] Pages to inspect:", len(pages))

    all_js_endpoints = set()
    all_forms = []
    all_csrf = []
    all_dom_xss = []
    all_header_issues = set()
    all_cookie_issues = set()

    for page in pages:
        print("[DEBUG] Inspecting page:", page)
        page_data = scan_page(page)

        all_js_endpoints.update(page_data["js_endpoints"])
        all_forms.extend(page_data["forms"])
        all_csrf.extend(page_data["csrf"])
        all_dom_xss.extend(page_data["dom_xss"])
        all_header_issues.update(page_data["security_headers"])
        all_cookie_issues.update(page_data["cookie_issues"])

    print("[+] Running directory brute force")
    dirs = dir_bruteforce(url)

    if pages:
        base_resp = fetch_page(url)
    else:
        base_resp = None

    print("[+] Scanning for open redirects and SSRF")
    redirects = []
    ssrf_vulns = []
    for page in pages:
        redirects.extend(test_open_redirect(page) or [])
        ssrf_vulns.extend(test_ssrf(page) or [])

    print("[+] Running async vulnerability scan")
    try:
        xss, sql = asyncio.run(asyncio.wait_for(run_async_scan(pages), timeout=300))
    except asyncio.TimeoutError:
        print("[!] Async scan timed out after 5 minutes, proceeding with partial results...")
        xss, sql = [], []

    # include form scan findings in top-level vulnerability counts
    form_xss = []
    form_sql = []
    for f in all_forms:
        form_xss.extend(f.get("xss", []))
        form_sql.extend(f.get("sql", []))

    xss_all = xss + form_xss
    sql_all = sql + form_sql

    sensitive = detect_sensitive_data(base_resp.text if base_resp else "")

    # 🔥 NEW: Advanced authorization and access control tests
    print("\n[*] Running advanced authorization tests...")
    idor_findings = scan_idor_vulnerabilities(links)
    auth_findings = scan_authorization_flaws(links)
    param_findings = scan_api_parameters(links)
    response_findings = scan_response_anomalies(links)
    
    # 🤖 NEW: Gemini AI-powered tests
    print("\n[*] Running Gemini AI analysis...")
    gemini_endpoint_findings = scan_with_gemini_endpoint_analysis(links)
    gemini_xss_findings = scan_stored_xss_with_gemini(all_forms, links)
    gemini_upload_findings = scan_file_uploads_with_gemini(links)
    gemini_chain_findings = detect_workflow_chains_with_gemini(links, list(all_js_endpoints))
    gemini_hidden_findings = identify_hidden_endpoints_with_gemini(list(all_js_endpoints))
    
    # Combine all findings
    security_issues = (idor_findings + auth_findings + param_findings + response_findings + 
                      gemini_endpoint_findings + gemini_xss_findings + 
                      gemini_upload_findings + gemini_chain_findings + gemini_hidden_findings)
    
    result = {
        "url": url,
        "status_code": base_resp.status_code if base_resp else 0,
        "links_found": links,
        "xss_vulnerabilities": xss_all,
        "sql_vulnerabilities": sql_all,
        "directories": dirs,
        "js_endpoints": sorted(all_js_endpoints),
        "dom_xss": all_dom_xss,
        "forms": all_forms,
        "csrf": all_csrf,
        "open_redirects": redirects,
        "subdomains": subs,
        "cookie_issues": sorted(all_cookie_issues),
        "security_header_issues": sorted(all_header_issues),
        "sensitive_data": sensitive,
        "ssrf": ssrf_vulns,
        # 🔥 NEW: Authorization & IDOR findings
        "idor_vulnerabilities": idor_findings,
        "authorization_flaws": auth_findings,
        "parameter_exploitation": param_findings,
        "information_leakage": [f for f in response_findings if f.get("type") in ["Information Leakage - Stack Trace", "Information Leakage - Database Error", "Information Leakage - File Path"]],
        # 🤖 NEW: Gemini AI findings
        "gemini_endpoint_analysis": gemini_endpoint_findings,
        "gemini_stored_xss": gemini_xss_findings,
        "gemini_file_uploads": gemini_upload_findings,
        "gemini_attack_chains": gemini_chain_findings,
        "gemini_hidden_endpoints": gemini_hidden_findings,
    }

    generate_html_report(result)
    generate_json_report(result)
    save_json(result)
    return result

def save_json(data):
    with open("reports/report.json", "w") as f:
        json.dump(data, f, indent=4)


def find_subdomains(url):

    from urllib.parse import urlparse

    domain = urlparse(url).netloc

    subs = ["api", "dev", "test", "staging"]

    found = []

    for s in subs:

        sub_url = f"http://{s}.{domain}"

        try:
            r = requests.get(sub_url, timeout=3, verify=False)

            if r.status_code < 400:
                print("[+] Subdomain found:", sub_url)
                found.append(sub_url)

        except:
            pass

    return found

def analyze_cookies(headers):

    issues = []

    cookies = headers.get("Set-Cookie", "")

    if "HttpOnly" not in cookies:
        issues.append("Missing HttpOnly")

    if "Secure" not in cookies:
        issues.append("Missing Secure")

    return issues

def detect_sensitive_data(html):

    patterns = [
        r"api_key\s*=\s*['\"](.*?)['\"]",
        r"token\s*=\s*['\"](.*?)['\"]",
        r"password\s*=\s*['\"](.*?)['\"]"
    ]

    found = []

    for p in patterns:
        matches = re.findall(p, html, re.IGNORECASE)
        found.extend(matches)

    return found