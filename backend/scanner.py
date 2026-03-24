import json

from flask import redirect
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import asyncio
import logging
import re
from async_scanner import run_async_scan
from report_generator import generate_html_report
from csrf_scanner import scan_csrf
from form_scanner import scan_forms
from payload_tester import session, HEADERS

logging.basicConfig(filename="scanner.log", level=logging.INFO)

# Limits for crawler
MAX_DEPTH = 2
MAX_LINKS = 20  # Reduced from 50 to speed up scanning

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
# JS endpoint discovery
# -----------------------------


def extract_js_endpoints(html):

    endpoints = []

    for line in html.split("\n"):
        if "/api/" in line or ".json" in line:
            endpoints.append(line.strip())

    return endpoints

def test_open_redirect(url, param):

    payload = "https://evil.com"
    test_url = f"{url.split('?')[0]}?{param}={payload}"

    try:
        r = requests.get(test_url, allow_redirects=False, timeout=5)

        if "Location" in r.headers and payload in r.headers["Location"]:
            return {
                "type": "Open Redirect",
                "url": test_url,
                "parameter": param
            }

    except:
        pass

    return None

# -----------------------------
# Directory brute force
# -----------------------------
def dir_bruteforce(base):

    found = []

    base_url = urlparse(base).scheme + '://' + urlparse(base).netloc

    for d in COMMON_DIRS:

        url = f"{base_url}/{d}"

        try:
            r = requests.get(url, timeout=3)

            if r.status_code == 200:
                print("[+] Directory found:", url)
                found.append(url)

        except:
            pass

    return found


# -----------------------------
# DOM XSS detection
# -----------------------------
def detect_dom_xss(html):

    patterns = ["document.write", "innerHTML", "eval(", "location"]

    return [p for p in patterns if p in html]


# -----------------------------
# MAIN
# -----------------------------
def scan_url(url):
    
    print("[+] Discovering subdomains")
    subs = find_subdomains(url)
    print("\n[+] Crawling site")
    links = crawl_links(url)
    print("[+] Testing SSRF")
    ssrf_vulns = []

    for link in links:
        r = test_ssrf(link)
        if r:
            ssrf_vulns.append(r)
    print("[+] Links discovered:", len(links))

    print("[+] Extracting JS endpoints")
    js = extract_js_endpoints(url)

    print("[+] Running directory brute force")
    dirs = dir_bruteforce(url)

    print("[+] Scanning forms")
    forms = scan_forms(url)
    print("[+] Scanning CSRF")
    csrf = scan_csrf(url)
    redirects = []

    # Use a base response for cookie and sensitive data checks, avoid unbound local variable
    base_resp = None
    try:
        base_resp = requests.get(url, timeout=5, proxies=PROXIES, verify=False)
    except:
        pass

    cookie_issues = analyze_cookies(base_resp.headers if base_resp else {})

    for link in links:
        r = test_open_redirect(link)
        if r:
            redirects.append(r)

    print("[+] Running async vulnerability scan")
    try:
        xss, sql = asyncio.run(asyncio.wait_for(run_async_scan(links), timeout=300))  # 5 minute timeout
    except asyncio.TimeoutError:
        print("[!] Async scan timed out after 5 minutes, proceeding with partial results...")
        xss, sql = [], []

    # include form scan findings in top-level vulnerability counts
    form_xss = []
    form_sql = []
    for f in forms:
        form_xss.extend(f.get("xss", []))
        form_sql.extend(f.get("sql", []))

    xss_all = xss + form_xss
    sql_all = sql + form_sql

    sensitive = detect_sensitive_data(base_resp.text if base_resp else "")
    dom = []
    try:
        r = requests.get(url)
        dom = detect_dom_xss(r.text)
    except:
        pass

    result = {
        "url": url,
        "status_code": base_resp.status_code if base_resp else 0,
        "links_found": links,
        "xss_vulnerabilities": xss_all,
        "sql_vulnerabilities": sql_all,
        "directories": dirs,
        "js_endpoints": js,
        "dom_xss": dom,
        "forms": forms,
        "csrf": csrf,
        "open_redirects": redirects,
        "subdomains": subs,
        "cookie_issues": cookie_issues,
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
            r = requests.get(sub_url, timeout=3)

            if r.status_code < 400:
                print("[+] Subdomain found:", sub_url)
                found.append(sub_url)

        except:
            pass

    return found
def test_open_redirect(url):

    payload = "https://evil.com"

    if "?" not in url:
        return None

    test_url = url + "&redirect=" + payload

    try:
        r = requests.get(test_url, allow_redirects=False)

        if "evil.com" in r.headers.get("Location", ""):
            return test_url

    except:
        pass

    return None

def test_ssrf(url):

    payload = "http://127.0.0.1"

    if "?" not in url:
        return None

    test_url = url + "&url=" + payload

    try:
        r = requests.get(test_url, timeout=5)

        if "127.0.0.1" in r.text:
            return test_url

    except:
        pass

    return None

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