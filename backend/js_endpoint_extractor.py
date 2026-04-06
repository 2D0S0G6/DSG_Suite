import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from payload_tester import HEADERS

API_PATTERNS = [
    r"/api/[a-zA-Z0-9_/]+",
    r"/v1/[a-zA-Z0-9_/]+",
    r"/v2/[a-zA-Z0-9_/]+"
]


def extract_js_endpoints(url):

    endpoints = set()

    try:
        r = requests.get(url, timeout=5, verify=False, headers=HEADERS)
        soup = BeautifulSoup(r.text, "html.parser")

        # External JS files
        scripts = soup.find_all("script", src=True)

        for s in scripts:

            js_url = urljoin(url, s["src"])

            try:
                js = requests.get(js_url, timeout=5, verify=False, headers=HEADERS).text

                for pattern in API_PATTERNS:
                    matches = re.findall(pattern, js)
                    endpoints.update(matches)

            except:
                pass

        # Inline scripts (IMPORTANT)
        inline_scripts = soup.find_all("script")

        for script in inline_scripts:

            code = script.text

            for pattern in API_PATTERNS:
                matches = re.findall(pattern, code)
                endpoints.update(matches)

    except:
        pass

    return list(endpoints)