import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json

def scan_csrf(url):
    """
    Comprehensive CSRF vulnerability scanner for modern web applications.
    Detects multiple CSRF protection bypass techniques and attack vectors.
    """
    vulnerabilities = []

    try:
        response = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        # 1. Check traditional form-based CSRF
        vulnerabilities.extend(_check_form_csrf(url, soup))

        # 2. Check for JSON CSRF vulnerabilities
        vulnerabilities.extend(_check_json_csrf(url, response))

        # 3. Check for CORS misconfigurations that could enable CSRF
        vulnerabilities.extend(_check_cors_csrf(url, response))

        # 4. Check for SameSite cookie bypass opportunities
        vulnerabilities.extend(_check_samesite_bypass(url, response))

        # 5. Check for login CSRF vulnerabilities
        vulnerabilities.extend(_check_login_csrf(url, soup))

        # 6. Check for CSRF in AJAX requests
        vulnerabilities.extend(_check_ajax_csrf(url, soup))

    except Exception as e:
        print(f"[!] CSRF scan error: {e}")

    return vulnerabilities

def _check_form_csrf(url, soup):
    """Check traditional form-based CSRF vulnerabilities."""
    vulnerabilities = []
    forms = soup.find_all("form")

    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()

        # Check POST forms for CSRF tokens
        if method == "post":
            inputs = form.find_all("input")
            has_csrf = False

            # Check for common CSRF token patterns
            csrf_patterns = [
                r'csrf[_-]?token', r'_token', r'authenticity[_-]?token',
                r'xsrf[_-]?token', r'__requestverificationtoken',
                r'state', r'nonce', r'token'
            ]

            for inp in inputs:
                name = inp.get("name", "").lower()
                inp_type = inp.get("type", "").lower()

                # Check input names
                for pattern in csrf_patterns:
                    if re.search(pattern, name, re.IGNORECASE):
                        has_csrf = True
                        break

                # Check for hidden inputs that might be tokens
                if inp_type == "hidden" and len(inp.get("value", "")) > 10:
                    has_csrf = True
                    break

            if not has_csrf:
                full_action = urljoin(url, action) if action else url
                vulnerabilities.append({
                    "type": "CSRF Vulnerability (Form)",
                    "url": full_action,
                    "method": method,
                    "explanation": "POST form lacks CSRF protection. Attackers can trick users into submitting unwanted requests.",
                    "severity": "High",
                    "remediation": "Add CSRF tokens, implement SameSite cookies, or validate Origin headers."
                })

    return vulnerabilities

def _check_json_csrf(url, response):
    """Check for JSON CSRF vulnerabilities."""
    vulnerabilities = []

    # Check if the site accepts JSON requests
    try:
        json_headers = {'Content-Type': 'application/json'}
        test_data = '{"test": "csrf"}'
        json_response = requests.post(url, data=test_data, headers=json_headers, timeout=5, verify=False)

        if json_response.status_code < 400:
            # Check if simple JSON POST works without authentication
            vulnerabilities.append({
                "type": "JSON CSRF Vulnerability",
                "url": url,
                "method": "POST",
                "explanation": "Application accepts JSON POST requests without CSRF protection. Attackers can use JSON with Array notation to bypass SameSite protections.",
                "severity": "High",
                "remediation": "Implement proper CORS validation, check Content-Type headers, or require authentication tokens."
            })
    except:
        pass

    return vulnerabilities

def _check_cors_csrf(url, response):
    """Check for CORS misconfigurations that enable CSRF."""
    vulnerabilities = []

    try:
        # Check CORS headers
        cors_origin = response.headers.get('Access-Control-Allow-Origin', '')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()

        if cors_origin == '*' and cors_credentials == 'true':
            vulnerabilities.append({
                "type": "CORS CSRF Vulnerability",
                "url": url,
                "method": "CORS",
                "explanation": "CORS allows credentials from any origin (*), enabling CSRF attacks via cross-origin requests.",
                "severity": "Critical",
                "remediation": "Restrict Access-Control-Allow-Origin to specific trusted domains, not '*'."
            })
    except:
        pass

    return vulnerabilities

def _check_samesite_bypass(url, response):
    """Check for SameSite cookie bypass opportunities."""
    vulnerabilities = []

    try:
        cookies = response.cookies
        for cookie in cookies:
            samesite = getattr(cookie, 'samesite', None)
            if not samesite or samesite.lower() not in ['strict', 'lax']:
                # Check if this is a session/auth cookie
                if any(keyword in cookie.name.lower() for keyword in ['session', 'auth', 'token', 'user']):
                    vulnerabilities.append({
                        "type": "SameSite CSRF Vulnerability",
                        "url": url,
                        "method": "Cookie",
                        "explanation": f"Cookie '{cookie.name}' lacks SameSite protection, vulnerable to CSRF attacks.",
                        "severity": "Medium",
                        "remediation": "Set SameSite=Strict or SameSite=Lax on authentication cookies."
                    })
    except:
        pass

    return vulnerabilities

def _check_login_csrf(url, soup):
    """Check for login CSRF vulnerabilities."""
    vulnerabilities = []

    # Look for login forms
    login_indicators = ['login', 'signin', 'auth', 'username', 'password']
    forms = soup.find_all("form")

    for form in forms:
        inputs = form.find_all("input")
        input_names = [inp.get("name", "").lower() for inp in inputs]

        # Check if this looks like a login form
        has_username = any('user' in name or 'email' in name for name in input_names)
        has_password = any('pass' in name for name in input_names)

        if has_username and has_password:
            action = form.get("action")
            method = form.get("method", "get").lower()

            # Check for login CSRF protection
            has_login_csrf_protection = False

            # Look for state parameters or other protections
            for inp in inputs:
                name = inp.get("name", "").lower()
                if any(keyword in name for keyword in ['state', 'nonce', 'token', 'csrf']):
                    has_login_csrf_protection = True
                    break

            if not has_login_csrf_protection:
                full_action = urljoin(url, action) if action else url
                vulnerabilities.append({
                    "type": "Login CSRF Vulnerability",
                    "url": full_action,
                    "method": method,
                    "explanation": "Login form lacks CSRF protection. Attackers can trick users into logging into attacker-controlled accounts.",
                    "severity": "High",
                    "remediation": "Add state parameters, implement proper CSRF tokens, or use Origin header validation."
                })

    return vulnerabilities

def _check_ajax_csrf(url, soup):
    """Check for CSRF in AJAX requests."""
    vulnerabilities = []

    # Look for AJAX requests in JavaScript
    scripts = soup.find_all("script")
    ajax_patterns = [
        r'\$\.ajax', r'\$\.post', r'\$\.get', r'XMLHttpRequest',
        r'fetch\(', r'axios\.', r'request\('
    ]

    for script in scripts:
        code = script.text
        for pattern in ajax_patterns:
            if re.search(pattern, code):
                # Check if CSRF tokens are included in AJAX calls
                if not re.search(r'csrf|token|_token', code, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "AJAX CSRF Vulnerability",
                        "url": url,
                        "method": "AJAX",
                        "explanation": "AJAX requests detected without apparent CSRF token inclusion, potentially vulnerable to CSRF.",
                        "severity": "Medium",
                        "remediation": "Include CSRF tokens in AJAX requests or implement proper CORS and Origin validation."
                    })
                    break

    return vulnerabilities