import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

from payload_tester import test_xss, test_sql
from form_scanner import scan_forms


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]

MAX_LINKS = 20


# -----------------------------
# Domain filter
# -----------------------------
def is_same_domain(base_url, target_url):

    base_domain = urlparse(base_url).netloc
    target_domain = urlparse(target_url).netloc

    return base_domain == target_domain


# -----------------------------
# Crawl links
# -----------------------------
def crawl_links(url):

    links = set()

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all("a", href=True):

            href = tag["href"]

            if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
                continue

            full_url = urljoin(url, href)

            if not full_url.startswith("http"):
                continue

            if is_same_domain(url, full_url):
                links.add(full_url)

            if len(links) >= MAX_LINKS:
                break

    except Exception as e:
        print("Crawl error:", e)

    return list(links)


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

    results = {
        "xss": [],
        "sql": []
    }

    params = detect_parameters(link)

    if params:

        xss_results = test_xss(link, params)
        sql_results = test_sql(link, params)

        results["xss"].extend(xss_results)
        results["sql"].extend(sql_results)

    return results


# -----------------------------
# Main scan function
# -----------------------------
def scan_url(url):

    result = {}

    try:

        response = requests.get(url, timeout=5)

        result["url"] = url
        result["status_code"] = response.status_code
        result["reachable"] = True
        result["content_length"] = len(response.content)
        result["headers"] = dict(response.headers)

        # Security headers
        result["missing_security_headers"] = check_security_headers(response.headers)

        # Crawl links
        links = crawl_links(url)
        result["links_found"] = links

        # Form scan
        result["form_vulnerabilities"] = scan_forms(url)

        all_xss = []
        all_sql = []

        # Scan main URL parameters
        main_params = detect_parameters(url)

        if main_params:
            all_xss.extend(test_xss(url, main_params))
            all_sql.extend(test_sql(url, main_params))

        # Threaded link scanning
        with ThreadPoolExecutor(max_workers=5) as executor:

            futures = [executor.submit(scan_link, link) for link in links]

            for future in futures:

                data = future.result()

                all_xss.extend(data["xss"])
                all_sql.extend(data["sql"])

        result["xss_vulnerabilities"] = all_xss
        result["sql_vulnerabilities"] = all_sql

    except Exception as e:

        result["url"] = url
        result["reachable"] = False
        result["error"] = str(e)

    return result