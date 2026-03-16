import re
import requests

ENDPOINT_REGEX = r'["\'](\/[a-zA-Z0-9_\-\/]+)["\']'

def extract_js_endpoints(url):

    endpoints = []

    try:

        r = requests.get(url, timeout=5)

        matches = re.findall(ENDPOINT_REGEX, r.text)

        for m in matches:
            if len(m) > 3:
                endpoints.append(m)

    except:
        pass

    return list(set(endpoints))