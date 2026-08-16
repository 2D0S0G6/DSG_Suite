import json
import re
import requests
from bs4 import BeautifulSoup

# Modern DOM XSS sources
SOURCES = [
    "location",
    "location.href",
    "location.hash",
    "location.search",
    "location.pathname",
    "document.referrer",
    "window.name",
    "document.URL",
    "document.documentURI",
    "document.cookie",
    "URLSearchParams",
    "FormData",
    "window.postMessage",
    "MessageEvent.data",
    "$route.params",
    "$route.query",
    "this.$route.params",
    "this.props.location",
]

# User-controlled sources for taint analysis
USER_SOURCES = [
    "location.search",
    "location.hash",
    "location.href",
    "window.location.search",
    "window.location.hash",
    "document.referrer",
    "document.cookie",
    "URLSearchParams",
    "FormData",
    "window.postMessage",
    "MessageEvent.data",
    "$route.params",
    "$route.query",
    "this.$route.params",
    "this.props.location",
]

SINKS = [
    "document.write",
    "document.writeln",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "eval",
    "setTimeout",
    "setInterval",
    "Function",
    "location.replace",
    "location.assign",
    "location.href",
    "window.open",
    "window.location",
    "document.location",
    "ReactDOM.render",
    "dangerouslySetInnerHTML",
    "document.createElement",
    "document.createElementNS",
    "Element.setAttribute",
    "Element.className",
    "Element.id",
    "Element.name",
    "addEventListener",
    "Element.style",
    "CSSStyleDeclaration.setProperty",
]

HIGH_CONFIDENCE_SINKS = [
    "document.write",
    "document.writeln",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "eval",
    "Function",
    "location.replace",
    "location.assign",
    "location.href",
    "window.open",
    "ReactDOM.render",
    "dangerouslySetInnerHTML",
]

AMBIGUOUS_SINKS = [
    "document.createElement",
    "document.createElementNS",
    "Element.setAttribute",
    "Element.className",
    "Element.id",
    "Element.name",
    "addEventListener",
    "Element.style",
    "CSSStyleDeclaration.setProperty",
]

FRAMEWORK_PATTERNS = {
    'vue': [
        r'v-html\s*=\s*["\'][^"\']*\{\{.*?\}\}[^"\']*["\']',
        r':html\s*=\s*["\'][^"\']*\{\{.*?\}\}[^"\']*["\']',
        r'this\.\$[a-zA-Z_][a-zA-Z0-9_]*\s*=',
        r'new\s+Vue\s*\(',
    ],
    'react': [
        r'dangerouslySetInnerHTML\s*=\s*\{',
        r'ReactDOM\.render\s*\(',
    ],
    'angular': [
        r'\[innerHTML\]\s*=\s*["\'][^"\']*\{\{.*?\}\}[^"\']*["\']',
        r'\$sce\.trustAsHtml\s*\(',
        r'this\.sanitizer\.bypassSecurityTrustHtml\s*\(',
    ],
}


def scan_dom_xss(url):
    findings = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")

        findings.extend(_analyze_inline_scripts(url, soup))
        findings.extend(_analyze_external_scripts(url, soup))
        findings.extend(_analyze_html_attributes(url, soup))
        findings.extend(_analyze_framework_patterns(url, response.text))
        findings.extend(_analyze_json_endpoints(url))
        findings.extend(_analyze_service_workers(url, soup))
    except Exception as e:
        findings.append({
            "type": "Error",
            "url": url,
            "severity": "Info",
            "explanation": f"Error scanning DOM XSS: {e}"
        })
    return findings


def _analyze_inline_scripts(url, soup):
    findings = []
    scripts = soup.find_all("script")

    for script in scripts:
        code = script.string or script.text or ""
        lines = code.split('\n')
        controlled_variables = {}

        for line in lines:
            for source in USER_SOURCES:
                if source in line:
                    var_matches = re.findall(r"\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b\s*(?:=|:)\s*.*" + re.escape(source), line)
                    for var_name in var_matches:
                        controlled_variables[var_name] = source

        for i, line in enumerate(lines):
            for sink in SINKS:
                if sink in line:
                    severity = "Low"
                    explanation = f"Found DOM sink-like pattern '{sink}'"
                    source_found = None

                    for source in USER_SOURCES:
                        if source in line:
                            severity = "High"
                            source_found = source
                            explanation = f"Found sink '{sink}' directly using user-controlled source '{source}'."
                            break

                    if severity != "High":
                        for var_name, src in controlled_variables.items():
                            if re.search(r"\b" + re.escape(var_name) + r"\b", line):
                                severity = "High"
                                source_found = src
                                explanation = f"Found sink '{sink}' using controlled variable '{var_name}' originating from '{src}'."
                                break

                    if sink in AMBIGUOUS_SINKS and severity == "Low":
                        if sink in ["document.createElement", "document.createElementNS"]:
                            m = re.search(r"\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b\s*=\s*" + re.escape(sink) + r"\(", line)
                            if m:
                                el_var = m.group(1)
                                for j in range(i + 1, min(i + 6, len(lines))):
                                    if re.search(rf"\b{re.escape(el_var)}\b\s*\.\s*(innerHTML|outerHTML|textContent|text)", lines[j]):
                                        for source in USER_SOURCES:
                                            if source in lines[j]:
                                                severity = "High"
                                                explanation = f"Created element '{el_var}' then assigned innerHTML from user-controlled source '{source}'."
                                                break
                                        for var2 in controlled_variables:
                                            if re.search(r"\b" + re.escape(var2) + r"\b", lines[j]):
                                                severity = "High"
                                                explanation = f"Created element '{el_var}' then assigned innerHTML using controlled variable '{var2}'."
                                                break
                                    if severity == "High":
                                        break
                        else:
                            continue

                    if '__proto__' in line or 'constructor.prototype' in line:
                        severity = "Critical"
                        explanation = f"Potential prototype pollution leading to DOM XSS via '{sink}'."

                    if severity == "Low":
                        surrounding = '\n'.join(lines[max(0, i - 5):min(len(lines), i + 5)])
                        if re.search(r'dangerouslySetInnerHTML|ReactDOM\.render|new\s+Vue|ng-app|\$scope', surrounding):
                            continue

                    findings.append({
                        "type": "DOM XSS Sink",
                        "sink": sink,
                        "line": i + 1,
                        "url": url,
                        "severity": severity,
                        "explanation": explanation
                    })

    return findings


def _analyze_external_scripts(url, soup):
    findings = []
    scripts = soup.find_all("script", {"src": True})
    for script in scripts:
        src = script.get("src")
        if src and any(param in src for param in ['?', '&', '=']):
            findings.append({
                "type": "External Script XSS",
                "url": url,
                "severity": "Medium",
                "explanation": f"External script source '{src}' contains query parameters and may be dynamic."
            })
    return findings


def _analyze_html_attributes(url, soup):
    findings = []
    event_handlers = [
        'onclick', 'onmouseover', 'onmouseout', 'onkeydown', 'onkeyup',
        'onload', 'onerror', 'onfocus', 'onblur', 'onsubmit', 'onchange'
    ]
    for handler in event_handlers:
        elements = soup.find_all(attrs={handler: True})
        for element in elements:
            handler_code = element.get(handler, "")
            for source in USER_SOURCES:
                if source in handler_code:
                    findings.append({
                        "type": "Event Handler XSS",
                        "url": url,
                        "severity": "High",
                        "explanation": f"Event handler '{handler}' contains user-controlled source '{source}'."
                    })
                    break
    return findings


def _analyze_framework_patterns(url, html_content):
    findings = []
    for framework, patterns in FRAMEWORK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, html_content, re.IGNORECASE | re.DOTALL):
                findings.append({
                    "type": f"Framework XSS ({framework.title()})",
                    "url": url,
                    "severity": "Medium",
                    "explanation": f"Detected framework-related pattern that may indicate risky XSS behavior: {pattern}"
                })
    return findings


def _analyze_json_endpoints(url):
    findings = []
    try:
        json_url = url if url.endswith('.json') else url.rstrip('/') + '.json'
        response = requests.get(json_url, timeout=8, verify=False)
        if response.headers.get('content-type', '').lower().startswith('application/json'):
            json_data = response.json()
            json_str = json.dumps(json_data)
            if '<' in json_str and '>' in json_str:
                findings.append({
                    "type": "JSON XSS",
                    "url": json_url,
                    "severity": "Medium",
                    "explanation": "JSON response contains HTML-like payloads that may be rendered unsafely in client-side code."
                })
    except Exception:
        pass
    return findings


def _analyze_service_workers(url, soup):
    findings = []
    scripts = soup.find_all("script")
    for script in scripts:
        code = script.string or script.text or ""
        if 'serviceWorker' in code and 'register' in code:
            findings.append({
                "type": "Service Worker XSS",
                "url": url,
                "severity": "Low",
                "explanation": "Service worker registration detected; if user input reaches service worker scripts it may increase attack surface."
            })
    return findings
