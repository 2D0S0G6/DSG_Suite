"""Scope & read-only boundary."""

from pipeline.scope import Scope


def test_seed_host_is_in_scope():
    s = Scope.from_seed("http://test.local/")
    assert s.is_in_scope("http://test.local/profile?id=1")
    assert s.is_in_scope("http://test.local/a/b/c")


def test_off_domain_is_rejected():
    s = Scope.from_seed("http://test.local/")
    assert not s.is_in_scope("https://evil.example.com/")
    assert not s.is_in_scope("http://sub.test.local/")  # subdomains off by default


def test_subdomains_opt_in():
    s = Scope.from_seed("http://test.local/", allow_subdomains=True)
    assert s.is_in_scope("http://api.test.local/v1")
    assert not s.is_in_scope("https://evil.example.com/")


def test_non_http_scheme_rejected():
    s = Scope.from_seed("http://test.local/")
    assert not s.is_in_scope("javascript:alert(1)")
    assert not s.is_in_scope("mailto:x@test.local")


def test_path_prefix_restriction():
    s = Scope.from_seed("http://test.local/", path_prefixes=["/app"])
    assert s.is_in_scope("http://test.local/app/dashboard")
    assert not s.is_in_scope("http://test.local/admin")


def test_destructive_detection():
    s = Scope.from_seed("http://test.local/")
    assert s.is_destructive("POST", "http://test.local/save")
    assert s.is_destructive("GET", "http://test.local/account/delete?id=3")
    assert s.is_destructive("GET", "http://test.local/logout")
    assert not s.is_destructive("GET", "http://test.local/profile?id=1")
