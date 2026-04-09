import requests
import re
from bs4 import BeautifulSoup

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
    "document.URLUnencoded",
    "document.baseURI",
    "document.cookie",
    "localStorage",
    "sessionStorage",
    "history.pushState",
    "history.replaceState"
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
    "setImmediate",
    "location.replace",
    "location.assign",
    "location.href",
    "window.location",
    "document.location",
    "execCommand",
    "open",
    "showModalDialog",
    "Function",
    "execScript",
    "crypto.generateCRMFRequest",
    "ScriptElement.src",
    "ScriptElement.text",
    "ScriptElement.textContent",
    "ScriptElement.innerText",
    "Range.createContextualFragment",
    "document.write",
    "document.writeln",
    "innerHTML",
    "outerHTML"
]


def scan_dom_xss(url):
    findings = []

    try:
        r = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = soup.find_all("script")

        for script in scripts:
            code = script.text
            lines = code.split('\n')
            controlled_variables = set()
            sink_findings = []

            # Find controlled variables (variables assigned from sources)
            for line in lines:
                # Check for variable declarations
                var_matches = re.findall(r'\bvar\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=', line)
                for var_name in var_matches:
                    for source in SOURCES:
                        if source in line:
                            controlled_variables.add(var_name)
                            break

                # Also check for assignments without var
                assign_matches = re.findall(r'\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=', line)
                for var_name in assign_matches:
                    for source in SOURCES:
                        if source in line:
                            controlled_variables.add(var_name)
                            break

            # Check for sinks and see if controlled variables are used
            for i, line in enumerate(lines):
                for sink in SINKS:
                    if sink in line:
                        risk_level = "Low"
                        explanation = f"Found dangerous DOM sink '{sink}'"
                        source_found = None

                        # Check if any controlled variable is used in this line
                        for var in controlled_variables:
                            if var in line:
                                risk_level = "High"
                                source_found = "controlled variable"
                                explanation = f"Found sink '{sink}' potentially using controlled variable '{var}' from source."
                                break

                        # Also check for direct source usage in sink
                        for source in SOURCES:
                            if source in line:
                                risk_level = "High"
                                source_found = source
                                explanation = f"Found sink '{sink}' directly using source '{source}'."
                                break

                        sink_findings.append({
                            "type": "DOM XSS Sink",
                            "sink": sink,
                            "line": i + 1,
                            "url": url,
                            "severity": risk_level,
                            "explanation": explanation
                        })

            # Also check for direct sinks without controlled variables
            for sink in SINKS:
                if sink in code and not any(finding['sink'] == sink for finding in sink_findings):
                    sink_findings.append({
                        "type": "DOM XSS Sink",
                        "sink": sink,
                        "url": url,
                        "severity": "Medium",
                        "explanation": f"Found dangerous DOM sink '{sink}'."
                    })

            findings.extend(sink_findings)

    except Exception as e:
        findings.append({
            "type": "Error",
            "url": url,
            "severity": "Info",
            "explanation": f"Error scanning DOM XSS: {str(e)}"
        })

    return findings