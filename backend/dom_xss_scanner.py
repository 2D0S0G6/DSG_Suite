import requests
import re
from bs4 import BeautifulSoup

SINKS = [
    "document.write",
    "innerHTML",
    "eval(",
    "location",
    "setTimeout",
    "setInterval"
]


def scan_dom_xss(url):

    findings = []

    try:

        r = requests.get(url, timeout=5, verify=False)

        soup = BeautifulSoup(r.text, "html.parser")

        scripts = soup.find_all("script")

        for script in scripts:

            code = script.text

            for sink in SINKS:

                if sink in code:

                    findings.append({
                        "type": "DOM XSS Sink",
                        "sink": sink,
                        "url": url
                    })

    except:
        pass

    return findings