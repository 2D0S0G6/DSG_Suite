import requests


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


# SQL Error Signatures
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
# XSS Testing
# -------------------------
def test_xss(url, parameters):

    vulnerabilities = []

    for param in parameters:

        for payload in XSS_PAYLOADS:

            try:

                test_url = f"{url}&{param}={payload}"

                response = requests.get(test_url, timeout=5)

                # Reflected payload detection
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

                test_url = f"{url}&{param}={payload}"

                response = requests.get(test_url, timeout=5)

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