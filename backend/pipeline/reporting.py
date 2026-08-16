"""Stage 11 - JSON / HTML report.

Assembles the validated findings and discovery metadata into a report payload,
writes a normalised ``findings`` JSON, and (optionally) renders the legacy
HTML/JSON reports via ``report_generator`` for backward compatibility.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List

from .models import SEVERITY_ORDER, Finding

# Map a finding type onto the legacy report_generator bucket it renders in.
_LEGACY_BUCKETS = {
    "dom xss": "dom_xss",
    "xss": "xss_vulnerabilities",
    "sql": "sql_vulnerabilities",
    "idor": "idor_vulnerabilities",
    "authorization": "authorization_flaws",
    "csrf": "csrf",
    "ssrf": "ssrf",
    "open redirect": "open_redirects",
}


def _bucket_for(finding: Finding) -> str:
    t = finding.type.lower()
    for needle, bucket in _LEGACY_BUCKETS.items():
        if needle in t:
            return bucket
    return "information_leakage"


def build_payload(
    url: str,
    status_code: int,
    findings: List[Finding],
    discovery: Dict,
    rejected: List[dict] = None,
) -> Dict:
    """Build a report payload compatible with ``report_generator`` that also
    carries the flat normalised findings and pipeline metadata."""
    payload: Dict = {
        "url": url,
        "status_code": status_code,
        "links_found": discovery.get("links", []),
        "directories": discovery.get("directories", []),
        "js_endpoints": discovery.get("js_endpoints", []),
        "subdomains": discovery.get("subdomains", []),
        "security_header_issues": discovery.get("security_header_issues", []),
        "cookie_issues": discovery.get("cookie_issues", []),
        # Legacy finding buckets — populated below.
        "xss_vulnerabilities": [],
        "sql_vulnerabilities": [],
        "idor_vulnerabilities": [],
        "authorization_flaws": [],
        "parameter_exploitation": [],
        "information_leakage": [],
        "csrf": [],
        "ssrf": [],
        "open_redirects": [],
        "dom_xss": [],
    }

    for finding in findings:
        payload.setdefault(_bucket_for(finding), []).append(finding.to_dict())

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    payload["normalized_findings"] = [f.to_dict() for f in findings]
    payload["rejected_findings"] = rejected or []
    payload["summary"] = {
        "total": len(findings),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "rejected": len(rejected or []),
    }
    return payload


def write_reports(payload: Dict, reports_dir: str = "reports") -> Dict[str, str]:
    """Write the normalised findings JSON and render legacy reports.

    Returns the paths written.  Legacy rendering is best-effort so a change in
    ``report_generator`` never breaks the pipeline.
    """
    os.makedirs(reports_dir, exist_ok=True)
    written: Dict[str, str] = {}

    findings_path = os.path.join(reports_dir, "findings.json")
    with open(findings_path, "w") as fh:
        json.dump(
            {
                "summary": payload.get("summary", {}),
                "findings": payload.get("normalized_findings", []),
                "rejected": payload.get("rejected_findings", []),
            },
            fh,
            indent=2,
        )
    written["findings"] = findings_path

    try:
        from report_generator import generate_html_report, generate_json_report

        generate_html_report(payload)
        generate_json_report(payload)
        written["html"] = os.path.join(reports_dir, "report.html")
        written["json"] = os.path.join(reports_dir, "report.json")
    except Exception:
        pass

    return written
