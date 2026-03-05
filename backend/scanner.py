import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

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
    for h in SECURITY_HEADERS:
        if h not in headers:
            missing.append(h)
    return missing


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

        # Crawling
        links = crawl_links(url)
        result["links_found"] = links

        # Parameter detection
        params = detect_parameters(url)
        result["parameters"] = params

        # Vulnerability checks
        result["sql_injection_possible"] = test_sqli(url)
        result["xss_possible"] = test_xss(url)

    except Exception as e:
        result["url"] = url
        result["reachable"] = False
        result["error"] = str(e)

    return result

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


def test_sqli(url):
    try:
        test_url = url + SQL_PAYLOAD
        r = requests.get(test_url, timeout=5)

        sql_errors = [
            "sql syntax",
            "mysql",
            "syntax error",
            "sqlite",
            "postgresql"
        ]

        for error in sql_errors:
            if error in r.text.lower():
                return True

    except:
        pass

    return False


def test_xss(url):
    try:
        test_url = url + XSS_PAYLOAD
        r = requests.get(test_url, timeout=5)

        if XSS_PAYLOAD in r.text:
            return True

    except:
        pass

    return False