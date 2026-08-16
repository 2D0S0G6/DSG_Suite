from pipeline import endpoint_discovery


def test_discover_captures_params():
    endpoints = endpoint_discovery.discover_endpoints(
        ["http://test.local/profile?id=1&tab=info"]
    )
    ep = endpoints[0]
    assert ep.params == ["id", "tab"]
    assert ep.method == "GET"


def test_js_endpoints_resolved_against_base():
    endpoints = endpoint_discovery.discover_endpoints(
        [], js_endpoints=["/api/v1/users"], base_url="http://test.local/home"
    )
    assert any(e.url == "http://test.local/api/v1/users" for e in endpoints)
    assert endpoints[0].source == "javascript"


def test_deduplicates_urls():
    endpoints = endpoint_discovery.discover_endpoints(
        ["http://test.local/a", "http://test.local/a/", "http://test.local/a#frag"]
    )
    assert len(endpoints) == 1


def test_looks_like_api():
    assert endpoint_discovery.looks_like_api("http://x/api/v1/users")
    assert endpoint_discovery.looks_like_api("http://x/graphql")
    assert not endpoint_discovery.looks_like_api("http://x/about")
