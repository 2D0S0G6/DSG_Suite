import requests
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from payload_tester import test_xss, test_sql
from form_scanner import scan_forms
from js_endpoint_extractor import extract_js_endpoints
from report_generator import generate_html_report
from dir_wordlist import DIR_WORDLIST
from param_wordlist import COMMON_PARAMETERS

from async_scanner import run_async_scan
from dom_xss_scanner import scan_dom_xss
from subdomain_scanner import discover_subdomains

visited_urls = set()
tested_payloads = set()
session = requests.Session()

HEADERS = {
    "User-Agent": "DSG-Scanner/2.0"
}

MAX_DEPTH = 2
MAX_LINKS = 25
TIMEOUT = 5

visited_urls = set()


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]


# --------------------------------
# Check same domain
# --------------------------------
def same_domain(base, target):

    return urlparse(base).netloc == urlparse(target).netloc


# --------------------------------
# Detect parameters
# --------------------------------
def detect_parameters(url):

    if "?" not in url:
        return []

    params = url.split("?")[1]

    found = []

    for p in params.split("&"):

        key = p.split("=")[0]

        if key not in found:
            found.append(key)

    return found


# --------------------------------
# Crawl website
# --------------------------------
def crawl_links(start_url):

    print("[+] Crawling site")

    visited = set()
    queue = [(start_url, 0)]

    links = []

    while queue:

        url, depth = queue.pop(0)

        if depth > MAX_DEPTH:
            continue

        if url in visited:
            continue

        visited.add(url)

        try:

            r = session.get(url, headers=HEADERS, timeout=TIMEOUT)

            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):

                link = urljoin(url, a["href"])

                if not link.startswith("http"):
                    continue

                if not same_domain(start_url, link):
                    continue

                if link not in visited and link not in links:

                    links.append(link)
                    queue.append((link, depth + 1))

                if len(links) >= MAX_LINKS:
                    return links

        except:
            pass

    return links


# --------------------------------
# Directory brute force
# --------------------------------
def dir_bruteforce(base_url):

    print("[+] Running directory brute force")

    found = []

    for word in DIR_WORDLIST:

        url = f"{base_url}/{word}"

        try:

            r = session.get(url, timeout=TIMEOUT)

            if r.status_code in [200, 301, 302] and len(r.text) > 200:

                print("[+] Directory found:", url)

                found.append(url)

        except:
            pass

    return found


# --------------------------------
# Security header check
# --------------------------------
def check_headers(headers):

    missing = []

    for h in SECURITY_HEADERS:

        if h not in headers:
            missing.append(h)

    return missing


# --------------------------------
# Parameter fuzzing
# --------------------------------
def fuzz_parameters(url):

    fuzzed = []

    for param in COMMON_PARAMETERS[:20]:

        if "?" in url:
            test_url = f"{url}&{param}=1"
        else:
            test_url = f"{url}?{param}=1"

        fuzzed.append({
            "parameter": param,
            "url": test_url
        })

    return fuzzed


# --------------------------------
# MAIN SCANNER
# --------------------------------
def scan_url(url):

    result = {}

    print("\n===============================")
    print(" DSG SUITE")
    print("===============================\n")

    print("[+] Target:", url)

    r = session.get(url, headers=HEADERS)

    result["url"] = url
    result["status_code"] = r.status_code
    result["headers"] = dict(r.headers)

    result["missing_security_headers"] = check_headers(r.headers)

    # Crawl
    links = crawl_links(url)

    print("[+] Links discovered:", len(links))

    result["links_found"] = links

    # JS endpoint discovery
    print("[+] Extracting JS endpoints")

    result["js_endpoints"] = extract_js_endpoints(url)

    # Directory brute force
    result["directories"] = dir_bruteforce(url)

    # Subdomain discovery
    domain = urlparse(url).netloc

    print("[+] Discovering subdomains")

    result["subdomains"] = discover_subdomains(domain)

    # Form scanning
    print("[+] Scanning forms")

    result["form_vulnerabilities"] = scan_forms(url)

    # Async vulnerability scanning
    print("[+] Running async vulnerability scan")

    xss, sql = asyncio.run(run_async_scan(links))

    result["xss_vulnerabilities"] = xss
    result["sql_vulnerabilities"] = sql

    # DOM XSS scan
    print("[+] Checking DOM XSS")

    dom_results = []

    for link in links:

        dom_results.extend(scan_dom_xss(link))

    result["dom_xss"] = dom_results

    # Parameter fuzzing
    fuzzed = []

    for link in links:

        fuzzed.extend(fuzz_parameters(link))

    result["fuzzed_parameters"] = fuzzed

    # Generate report
    generate_html_report(result)

    print("\n[+] Scan completed")
    print("[+] Report saved: reports/report.html\n")

    return result