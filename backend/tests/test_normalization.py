from pipeline import normalization


def test_maps_alternate_keys():
    f = normalization.normalize_one(
        {"type": "IDOR", "endpoint": "http://x/api", "risk_level": "high",
         "explanation": "bad", "poc": "GET /api"}
    )
    assert f.url == "http://x/api"
    assert f.severity == "high"
    assert f.description == "bad"
    assert f.evidence == "GET /api"


def test_severity_aliasing_and_fallback():
    assert normalization.normalize_severity("CRITICAL") == "critical"
    assert normalization.normalize_severity("moderate") == "medium"
    assert normalization.normalize_severity("banana") == "medium"


def test_confidence_fallback():
    assert normalization.normalize_confidence("high") == "high"
    assert normalization.normalize_confidence("") == "medium"


def test_fingerprint_is_stable_and_set():
    a = normalization.normalize_one({"type": "XSS", "url": "http://x/a"})
    b = normalization.normalize_one({"type": "xss", "url": "http://x/a/"})
    assert a.fingerprint and a.fingerprint == b.fingerprint


def test_title_defaults_to_type():
    f = normalization.normalize_one({"type": "SSRF", "url": "http://x"})
    assert f.title == "SSRF"


def test_normalize_skips_empty():
    assert normalization.normalize([None, {}, {"type": "X", "url": "u"}])
