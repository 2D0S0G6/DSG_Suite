import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

from payload_tester import test_xss, test_sql
from form_scanner import scan_forms
from param_wordlist import COMMON_PARAMETERS

session = requests.Session()
MAX_DEPTH = 2
HEADERS = {
    "User-Agent": "DSG-Scanner/1.0"
}
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]

MAX_LINKS = 20

HEADERS = {
    "User-Agent": "DSG-Scanner/1.0"
}


# -----------------------------
# Domain filter
# -----------------------------
def is_same_domain(base_url, target_url):

    base_domain = urlparse(base_url).netloc
    target_domain = urlparse(target_url).netloc

    return base_domain == target_domain


# -----------------------------
# Parameter fuzzing
# -----------------------------
def fuzz_parameters(url):

    discovered = []

    for param in COMMON_PARAMETERS:

        test_url = f"{url}?{param}=1"

        try:
            r = session.get(test_url, headers=HEADERS, timeout=5)

            if r.status_code == 200 and len(r.text) > 100:
                discovered.append((param, test_url))

        except:
            pass

    return discovered


# -----------------------------
# Crawl links
# -----------------------------
def crawl_links(start_url):

    visited = set()
    to_visit = [(start_url, 0)]

    links = []

    while to_visit:

        url, depth = to_visit.pop(0)

        if depth > MAX_DEPTH:
            continue

        if url in visited:
            continue

        visited.add(url)

        try:
            response = session.get(url, headers=HEADERS, timeout=5)

            soup = BeautifulSoup(response.text, "html.parser")

            for tag in soup.find_all("a", href=True):

                href = tag["href"]

                if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
                    continue

                full_url = urljoin(url, href)

                if not full_url.startswith("http"):
                    continue

                if not is_same_domain(start_url, full_url):
                    continue

                if full_url not in visited:

                    links.append(full_url)
                    to_visit.append((full_url, depth + 1))

                if len(links) >= MAX_LINKS:
                    return links

        except:
            pass

    return links


# -----------------------------
# Check security headers
# -----------------------------
def check_security_headers(headers):

    missing = []

    for header in SECURITY_HEADERS:
        if header not in headers:
            missing.append(header)

    return missing


# -----------------------------
# Detect parameters
# -----------------------------
def detect_parameters(url):

    if "?" not in url:
        return []

    try:
        params_part = url.split("?", 1)[1]

        param_list = params_part.split("&")

        parameters = []

        for p in param_list:
            key = p.split("=")[0]
            parameters.append(key)

        return parameters

    except:
        return []


# -----------------------------
# Scan single link
# -----------------------------
def scan_link(link):

    print("Scanning:", link)

    results = {
        "xss": [],
        "sql": []
    }

    params = detect_parameters(link)

    if params:

        results["xss"].extend(test_xss(link, params))
        results["sql"].extend(test_sql(link, params))

    return results


# -----------------------------
# Main scan function
# -----------------------------
def scan_url(url):

    result = {}

    try:

        response = session.get(url, headers=HEADERS, timeout=10)

        result["url"] = url
        result["status_code"] = response.status_code
        result["reachable"] = True
        result["content_length"] = len(response.content)
        result["headers"] = dict(response.headers)

        # Security headers
        result["missing_security_headers"] = check_security_headers(response.headers)

        # Crawl
        links = crawl_links(url)
        result["links_found"] = links

        # Forms
        result["form_vulnerabilities"] = scan_forms(url)

        all_xss = []
        all_sql = []

        # Scan main URL parameters
        main_params = detect_parameters(url)

        if main_params:
            all_xss.extend(test_xss(url, main_params))
            all_sql.extend(test_sql(url, main_params))

        # -----------------------------
        # Threaded link scanning
        # -----------------------------
        with ThreadPoolExecutor(max_workers=5) as executor:

            futures = [executor.submit(scan_link, link) for link in links]

            for future in futures:

                try:
                    data = future.result()

                    all_xss.extend(data["xss"])
                    all_sql.extend(data["sql"])

                except:
                    pass

        # -----------------------------
        # Parameter fuzzing
        # -----------------------------
        fuzzed_urls = []
        scanned = set()

        for link in links:

            discovered = fuzz_parameters(link)

            for param, fuzz_url in discovered:

                if fuzz_url in scanned:
                    continue

                scanned.add(fuzz_url)

                fuzzed_urls.append({
                    "parameter": param,
                    "url": fuzz_url
                })

                all_xss.extend(test_xss(fuzz_url, [param]))
                all_sql.extend(test_sql(fuzz_url, [param]))

        result["fuzzed_parameters"] = fuzzed_urls

        result["xss_vulnerabilities"] = all_xss
        result["sql_vulnerabilities"] = all_sql

    except Exception as e:

        result["url"] = url
        result["reachable"] = False
        result["error"] = str(e)

    return result