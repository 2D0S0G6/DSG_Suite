import json
import os

from pipeline import reporting
from pipeline.normalization import normalize_one


def _findings():
    return [
        normalize_one({"type": "DOM XSS", "url": "http://x/a", "severity": "high", "evidence": "innerHTML"}),
        normalize_one({"type": "Hardcoded Secret", "url": "http://x/a.js", "severity": "critical", "evidence": "key"}),
    ]


def test_build_payload_buckets_and_summary():
    payload = reporting.build_payload(
        "http://x/", 200, _findings(), {"links": ["http://x/"]}
    )
    assert payload["dom_xss"]
    assert payload["information_leakage"]  # secret bucketed here
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["critical"] == 1
    assert payload["summary"]["high"] == 1
    assert payload["links_found"] == ["http://x/"]


def test_write_reports_emits_findings_json(tmp_path):
    payload = reporting.build_payload("http://x/", 200, _findings(), {})
    written = reporting.write_reports(payload, reports_dir=str(tmp_path))
    assert os.path.exists(written["findings"])
    with open(written["findings"]) as fh:
        data = json.load(fh)
    assert data["summary"]["total"] == 2
    assert len(data["findings"]) == 2
