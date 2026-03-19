import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import asyncio
import logging
import re
from async_scanner import run_async_scan
from form_scanner import scan_forms

logging.basicConfig(filename="scanner.log", level=logging.INFO)

COMMON_DIRS = ["admin", "dashboard", "backup", "config"]

PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}
# -----------------------------
# Crawl
# -----------------------------
def crawl_links(url):

    visited = set()
    links = []

    try:
        r = requests.get(url, timeout=5, proxies=PROXIES, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")

        for tag in soup.find_all("a", href=True):

            full = urljoin(url, tag["href"])

            if full not in visited and full.startswith("http"):
                visited.add(full)
                links.append(full)

    except:
        pass

    return links[:25]


# -----------------------------
# JS endpoint discovery
# -----------------------------


def extract_js_endpoints(url):

    endpoints = []

    try:
        r = requests.get(url, timeout=5)

        matches = re.findall(r'["\'](\/api\/[^"\']+)["\']', r.text)

        endpoints.extend(matches)

    except:
        pass

    return list(set(endpoints))


# -----------------------------
# Directory brute force
# -----------------------------
def dir_bruteforce(base):

    found = []

    for d in COMMON_DIRS:

        url = f"{base}/{d}"

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
# HTML Report
# -----------------------------
def generate_report(data):

    html = f"""
    <html>
    <head><title>DSG Report</title></head>
    <body>

    <h1>DSG Scan Report</h1>
    <p><b>Target:</b> {data['url']}</p>

    <h2>XSS</h2>
    <pre>{data['xss_vulnerabilities']}</pre>

    <h2>SQLi</h2>
    <pre>{data['sql_vulnerabilities']}</pre>

    <h2>Directories</h2>
    <pre>{data['directories']}</pre>

    <h2>JS Endpoints</h2>
    <pre>{data['js_endpoints']}</pre>

    </body>
    </html>
    """

    with open("reports/report.html", "w") as f:
        f.write(html)


# -----------------------------
# MAIN
# -----------------------------
def scan_url(url):
    print("[+] Discovering subdomains")
    subs = find_subdomains(url)
    print("\n[+] Crawling site")
    links = crawl_links(url)

    print("[+] Links discovered:", len(links))

    print("[+] Extracting JS endpoints")
    js = extract_js_endpoints(url)

    print("[+] Running directory brute force")
    dirs = dir_bruteforce(url)

    print("[+] Scanning forms")
    forms = scan_forms(url)
    redirects = []

    for link in links:
        r = test_open_redirect(link)
        if r:
            redirects.append(r)
    print("[+] Running async vulnerability scan")
    xss, sql = asyncio.run(run_async_scan(links))

    dom = []
    try:
        r = requests.get(url)
        dom = detect_dom_xss(r.text)
    except:
        pass

    result = {
        "url": url,
        "links_found": links,
        "xss_vulnerabilities": xss,
        "sql_vulnerabilities": sql,
        "directories": dirs,
        "js_endpoints": js,
        "dom_xss": dom,
        "forms": forms,
        "open_redirects": redirects,
        "subdomains": subs
    }

    generate_report(result)

    return result

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