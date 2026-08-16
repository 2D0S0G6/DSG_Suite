from pipeline import validation
from pipeline.normalization import normalize_one


def test_rejects_unknown_type():
    f = normalize_one({"type": "Unknown", "url": "http://x"})
    valid, rejected = validation.validate([f])
    assert not valid
    assert rejected and "type" in rejected[0]["reason"]


def test_rejects_findings_without_anchor():
    f = normalize_one({"type": "XSS"})  # no url, no evidence
    valid, rejected = validation.validate([f])
    assert not valid
    assert rejected


def test_accepts_valid_finding():
    f = normalize_one({"type": "XSS", "url": "http://x/a", "evidence": "payload"})
    valid, rejected = validation.validate([f])
    assert len(valid) == 1
    assert not rejected


def test_drop_low_confidence_flag():
    f = normalize_one({"type": "XSS", "url": "http://x/a", "confidence": "low"})
    valid, rejected = validation.validate([f], drop_low_confidence=True)
    assert not valid
    assert rejected[0]["reason"] == "below confidence threshold"

    valid2, _ = validation.validate([f], drop_low_confidence=False)
    assert len(valid2) == 1
