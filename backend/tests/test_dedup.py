from pipeline import dedup
from pipeline.normalization import normalize_one


def test_duplicates_collapse():
    a = normalize_one({"type": "XSS", "url": "http://x/a", "source": "regex"})
    b = normalize_one({"type": "XSS", "url": "http://x/a", "source": "regex"})
    out = dedup.deduplicate([a, b])
    assert len(out) == 1


def test_merge_keeps_stronger_severity_and_sources():
    a = normalize_one({"type": "XSS", "url": "http://x/a", "severity": "medium", "source": "regex"})
    b = normalize_one({"type": "XSS", "url": "http://x/a", "severity": "high", "source": "gemini"})
    out = dedup.deduplicate([a, b])
    assert len(out) == 1
    assert out[0].severity == "high"
    # corroboration by two distinct sources raises confidence
    assert out[0].confidence == "high"
    assert set(out[0].metadata["sources"]) == {"regex", "gemini"}


def test_distinct_findings_preserved_and_sorted():
    a = normalize_one({"type": "XSS", "url": "http://x/a", "severity": "low"})
    b = normalize_one({"type": "SQLi", "url": "http://x/b", "severity": "critical"})
    out = dedup.deduplicate([a, b])
    assert len(out) == 2
    assert out[0].severity == "critical"  # sorted most-severe first
