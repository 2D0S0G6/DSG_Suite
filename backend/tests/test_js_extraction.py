from pipeline import js_extraction


def test_extract_external_and_inline(fetch, site):
    pages = {"http://test.local/": site["http://test.local/"][2]}
    assets = js_extraction.extract_js_assets(pages, fetch=fetch)

    externals = [a for a in assets if not a.inline]
    inlines = [a for a in assets if a.inline]

    assert any(a.url == "http://test.local/app.js" for a in externals)
    assert externals and "api_key" in externals[0].content
    assert inlines and "location.hash" in inlines[0].content


def test_external_script_fetched_once(fetch, site):
    html = site["http://test.local/"][2]
    pages = {"http://test.local/": html, "http://test.local/dup": html}
    assets = js_extraction.extract_js_assets(pages, fetch=fetch)
    app_js = [a for a in assets if a.url == "http://test.local/app.js"]
    assert len(app_js) == 1


def test_mine_endpoints(fetch, site):
    pages = {"http://test.local/": site["http://test.local/"][2]}
    assets = js_extraction.extract_js_assets(pages, fetch=fetch)
    endpoints = js_extraction.mine_endpoints(assets)
    assert any("/api/v1/users" in e for e in endpoints)
    assert any("/api/v1/orders" in e for e in endpoints)
