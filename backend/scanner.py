import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from payload_tester import test_xss, test_sql, test_time_sql
from form_scanner import scan_forms
from param_wordlist import COMMON_PARAMETERS


# -----------------------------
# Global config
# -----------------------------
session = requests.Session()

HEADERS = {
    "User-Agent": "DSG-Scanner/1.0"
}

MAX_DEPTH = 2
MAX_LINKS = 20
REQUEST_TIMEOUT = 3
MAX_THREADS = 10


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]


# -----------------------------
# Domain filter
# -----------------------------
def is_same_domain(base_url, target_url):

    base_domain = urlparse(base_url).netloc
    target_domain = urlparse(target_url).netloc

    return base_domain == target_domain


# -----------------------------
# Safe URL builder
# -----------------------------
def build_url(url, param, value):

    if "?" in url:
        return f"{url}&{param}={value}"
    else:
        return f"{url}?{param}={value}"


# -----------------------------
# Parameter fuzzing
# -----------------------------
def fuzz_parameters(url):

    discovered = []

    for param in COMMON_PARAMETERS[:30]:   # limit fuzz size

        test_url = build_url(url, param, "1")

        print("Fuzzing:", test_url)

        try:

            r = session.get(test_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)

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

            response = session.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)

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
# Security header check
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

        parameters = set()

        for p in param_list:
            key = p.split("=")[0]
            parameters.add(key)

        return list(parameters)

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
        results["sql"].extend(test_time_sql(link, params))

    return results


# -----------------------------
# Main scan function
# -----------------------------
def scan_url(url):

    result = {}

    try:

        response = session.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)

        result["url"] = url
        result["status_code"] = response.status_code
        result["reachable"] = True
        result["content_length"] = len(response.content)
        result["headers"] = dict(response.headers)

        # security headers
        result["missing_security_headers"] = check_security_headers(response.headers)

        # crawl site
        links = crawl_links(url)
        result["links_found"] = links

        # scan forms
        result["form_vulnerabilities"] = scan_forms(url)

        all_xss = []
        all_sql = []

        # scan main URL parameters
        main_params = detect_parameters(url)

        if main_params:

            all_xss.extend(test_xss(url, main_params))
            all_sql.extend(test_sql(url, main_params))
            all_sql.extend(test_time_sql(url, main_params))

        # -----------------------------
        # threaded link scanning
        # -----------------------------
        with ThreadPoolExecutor(MAX_THREADS) as executor:

            futures = [executor.submit(scan_link, link) for link in links]

            for future in as_completed(futures):

                try:

                    data = future.result()

                    all_xss.extend(data["xss"])
                    all_sql.extend(data["sql"])

                except:
                    pass


        # -----------------------------
        # threaded parameter fuzzing
        # -----------------------------
        fuzzed_urls = []
        scanned = set()

        with ThreadPoolExecutor(MAX_THREADS) as executor:

            futures = [executor.submit(fuzz_parameters, link) for link in links]

            for future in as_completed(futures):

                discovered = future.result()

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