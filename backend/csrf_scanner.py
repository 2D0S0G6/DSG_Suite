import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def scan_csrf(url):
    """
    Scan for CSRF vulnerabilities by checking forms for missing CSRF tokens.
    """
    vulnerabilities = []

    try:
        response = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()

            # Only check POST forms for CSRF
            if method == "post":
                inputs = form.find_all("input")
                has_csrf = any(inp.get("name", "").lower() in ["csrf_token", "csrf", "_token", "authenticity_token"] for inp in inputs)

                if not has_csrf:
                    full_action = urljoin(url, action) if action else url
                    vulnerabilities.append({
                        "type": "CSRF Vulnerability",
                        "url": full_action,
                        "method": method,
                        "explanation": "The form does not include a CSRF token, allowing attackers to trick users into performing unwanted actions.",
                        "severity": "Medium",
                        "remediation": "Add a unique CSRF token to each form and validate it on the server side."
                    })

    except Exception as e:
        print(f"[!] CSRF scan error: {e}")

    return vulnerabilities