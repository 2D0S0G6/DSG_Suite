"""Secret redaction boundary."""

from pipeline.redaction import redact, redact_obj, scan_secrets


def test_redacts_common_secret_shapes():
    samples = [
        "var api_key='SUPERSECRETKEY123456';",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
        "key=AKIAIOSFODNN7EXAMPLE",
        "gsk_abcdefghijklmnopqrstuvwxyz0123456789",
    ]
    for s in samples:
        out = redact(s)
        assert "[REDACTED:" in out
    assert "SUPERSECRETKEY123456" not in redact(samples[0])


def test_redact_obj_is_recursive():
    obj = {"a": ["tok=AKIAIOSFODNN7EXAMPLE", {"b": "clean"}], "c": 5}
    out = redact_obj(obj)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(out)
    assert out["c"] == 5
    assert out["a"][1]["b"] == "clean"


def test_scan_secrets_reports_without_value():
    hits = scan_secrets("var api_key='SUPERSECRETKEY123456';")
    assert hits
    assert all("SUPERSECRETKEY123456" not in h.get("hint", "") for h in hits)
    assert all("kind" in h for h in hits)


def test_clean_text_untouched():
    text = "function add(a, b) { return a + b; }"
    assert redact(text) == text
