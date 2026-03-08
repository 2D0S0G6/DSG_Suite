import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
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


def crawl_links(url):
    links = set()

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all("a", href=True):

            href = tag["href"]

            # Skip unwanted links
            if href.startswith("#") or href.startswith("mailto:") or href.startswith("javascript:"):
                continue

            full_url = urljoin(url, href)

            if full_url.startswith("http"):
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

    try:
        params = url.split("?", 1)[1]
        param_list = params.split("&")

        parameters = []

        for p in param_list:
            key = p.split("=")[0]
            parameters.append(key)

        return parameters

    except:
        return []


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
        result["links_found"] = links[:MAX_LINKS]

        # Form scanning
        form_results = scan_forms(url)
        result["form_vulnerabilities"] = form_results

        # Detect parameters in main URL
        main_params = detect_parameters(url)
        result["parameters"] = main_params

        all_xss = set()
        all_sql = set()

        # Scan main URL
        if main_params:
            all_xss.update(test_xss(url, main_params))
            all_sql.update(test_sql(url, main_params))

        # Scan crawled links
        for link in links[:MAX_LINKS]:

            params = detect_parameters(link)

            if params:
                xss_results = test_xss(link, params)
                sql_results = test_sql(link, params)

                all_xss.update(xss_results)
                all_sql.update(sql_results)

        result["xss_vulnerabilities"] = list(all_xss)
        result["sql_vulnerabilities"] = list(all_sql)

    except Exception as e:

        result["url"] = url
        result["reachable"] = False
        result["error"] = str(e)

    return result