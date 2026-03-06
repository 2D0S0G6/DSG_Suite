import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from payload_tester import test_xss, test_sql

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]


def crawl_links(url):
    links = set()

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all("a", href=True):
            full_url = urljoin(url, tag["href"])
            links.add(full_url)

    except Exception as e:
        print("Crawl error:", e)

    return list(links)


def check_security_headers(headers):

    missing = []

    for header in SECURITY_HEADERS:
        if header not in headers:
            missing.append(header)

    return missing


def detect_parameters(url):

    if "?" not in url:
        return []

    base, params = url.split("?", 1)
    param_list = params.split("&")

    parameters = []

    for p in param_list:
        key = p.split("=")[0]
        parameters.append(key)

    return parameters


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

        # Detect parameters
        parameters = detect_parameters(url)
        result["parameters"] = parameters

        # Payload testing
        xss_results = test_xss(url, parameters)
        sql_results = test_sql(url, parameters)

        result["xss_vulnerabilities"] = xss_results
        result["sql_vulnerabilities"] = sql_results

    except Exception as e:

        result["url"] = url
        result["reachable"] = False
        result["error"] = str(e)

    return result