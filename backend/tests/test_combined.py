"""Combined-engine adapter tests.

The combined scan runs offline here via ``run_legacy=False`` + an injected
``fetch``, so only the merge/backbone path is exercised (no network). A separate
unit test proves the cross-engine corroboration that is the whole point of the
adapter.
"""

from combined_scan import legacy_raw_findings, run_combined
from pipeline import PipelineConfig, dedup, normalization


def test_combined_runs_offline_pipeline_only(fetch, tmp_path):
    cfg = PipelineConfig(max_links=10, chunk_size=400, chunk_overlap=50)
    result = run_combined(
        "http://test.local/",
        config=cfg,
        fetch=fetch,
        run_legacy=False,          # keep it offline / no network
        write=True,
        reports_dir=str(tmp_path),
    )

    # The pipeline half produced findings and the report is coherent.
    types = {f["type"] for f in result["normalized_findings"]}
    assert "DOM XSS" in types
    assert "Hardcoded Secret" in types
    assert result["summary"]["total"] == len(result["normalized_findings"])

    # Engine breakdown is reported; legacy contributed nothing when skipped.
    assert result["engines"]["legacy_findings"] == 0
    assert result["engines"]["pipeline_findings"] > 0
    assert result["engines"]["combined_unique"] == result["summary"]["total"]


def test_legacy_raw_findings_flattening():
    legacy_result = {
        "xss_vulnerabilities": [{"url": "http://t/x", "parameter": "q", "payload": "<script>"}],
        "sql_vulnerabilities": [{"url": "http://t/s", "parameter": "id"}],
        "gemini_attack_chains": [{"endpoint": "http://t/a", "name": "chain"}],
        "unrelated_key": [{"noise": True}],
    }
    raw = legacy_raw_findings(legacy_result)

    by_type = {r["type"] for r in raw}
    assert by_type == {"XSS", "SQL Injection", "Attack Chain"}
    # Provenance is tagged so dedup can tell the engines apart.
    assert all(r["source"] in ("legacy-active", "legacy-gemini") for r in raw)
    assert next(r for r in raw if r["type"] == "Attack Chain")["source"] == "legacy-gemini"


def test_cross_engine_corroboration_raises_confidence():
    """A pipeline finding and a legacy finding on the same fingerprint merge into
    one finding, and the independent second source boosts confidence to high."""
    pipeline_raw = {
        "type": "SQL Injection",
        "url": "http://test.local/api/v1/users?id=1",
        "parameter": "id",
        "severity": "high",
        "confidence": "low",
        "source": "gemini-rag",
    }
    legacy_raw = {
        "type": "SQL Injection",
        "url": "http://test.local/api/v1/users?id=1",
        "parameter": "id",
        "severity": "critical",
        "confidence": "medium",
        "source": "legacy-active",
    }

    findings = normalization.normalize([pipeline_raw, legacy_raw])
    # Same fingerprint (type + normalised url + parameter).
    assert findings[0].fingerprint == findings[1].fingerprint

    merged = dedup.deduplicate(findings)
    assert len(merged) == 1
    result = merged[0]
    assert result.severity == "critical"          # strongest severity wins
    assert result.confidence == "high"            # corroboration bump
    assert set(result.metadata["sources"]) == {"gemini-rag", "legacy-active"}
