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
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "'><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>"
]


# -------------------------
# SQL Payloads
# -------------------------
SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "'; DROP TABLE users--",
    "' AND 1=0 UNION SELECT username, password FROM users--"
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
                        "url": test_url,
                        "explanation": "The response took significantly longer than expected, indicating the SQL payload caused a delay (e.g., SLEEP function), confirming blind SQL injection vulnerability.",
                        "severity": "High",
                        "remediation": "Use prepared statements and avoid dynamic SQL queries with user input."
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
                        "url": test_url,
                        "explanation": "The XSS payload was reflected in the server's response without proper HTML encoding or sanitization, allowing potential script execution in the user's browser.",
                        "severity": "High",
                        "remediation": "Implement output encoding (e.g., HTML entity encoding) or use a library like DOMPurify to sanitize user inputs."
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
                            "evidence": error,
                            "explanation": f"An SQL error ('{error}') was triggered by the payload, indicating the application is vulnerable to SQL injection as user input is directly concatenated into SQL queries.",
                            "severity": "Critical",
                            "remediation": "Use prepared statements or parameterized queries, and validate/sanitize all user inputs."
                        })

                        break

            except:
                pass

    return vulnerabilities

def test_error_sql(url, params):

    errors = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-01756",
        "SQLite error",
        "UNEXPECTED TOKEN",
        "ODBC SQL Server Driver"
]
    

    vulns = []

    for p in params:

        test_url = f"{url}&{p}='"

        try:
            r = requests.get(test_url, timeout=5)

            for e in errors:
                if e.lower() in r.text.lower():
                    vulns.append({
                        "parameter": p,
                        "type": "Error-based SQLi",
                        "url": test_url,
                        "explanation": f"An SQL error ('{e}') was revealed by injecting a single quote, indicating improper handling of user input in SQL queries.",
                        "severity": "Critical",
                        "remediation": "Use parameterized queries and input validation to prevent SQL injection."
                    })

        except:
            pass

    return vulns