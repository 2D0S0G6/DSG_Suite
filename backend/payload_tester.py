import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from payloads import XSS_PAYLOADS, SQL_PAYLOADS


def inject_payload(url, param, payload):
    
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    query[param] = payload

    new_query = urlencode(query, doseq=True)

    new_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment
    ))

    return new_url


def test_xss(url, parameters):

    results = []

    for param in parameters:
        for payload in XSS_PAYLOADS:

            test_url = inject_payload(url, param, payload)

            try:
                r = requests.get(test_url, timeout=5)

                if payload in r.text:
                    results.append({
                        "parameter": param,
                        "payload": payload,
                        "url": test_url
                    })

            except:
                pass

    return results


def test_sql(url, parameters):

    results = []

    for param in parameters:
        for payload in SQL_PAYLOADS:

            test_url = inject_payload(url, param, payload)

            try:
                r = requests.get(test_url, timeout=5)

                errors = [
                    "sql syntax",
                    "mysql",
                    "warning",
                    "odbc",
                    "pdo",
                    "sql error"
                ]

                for e in errors:
                    if e.lower() in r.text.lower():
                        results.append({
                            "parameter": param,
                            "payload": payload,
                            "url": test_url
                        })
                        break

            except:
                pass

    return results