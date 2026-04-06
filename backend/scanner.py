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
from report_generator import generate_html_report
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


# -----------------------------
# MAIN
# -----------------------------
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
        "ssrf": ssrf_vulns
    }

    generate_html_report(result)
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