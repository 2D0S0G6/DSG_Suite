from pipeline import crawler


def test_crawl_includes_start_and_same_domain(fetch):
    links = crawler.crawl("http://test.local/", fetch=fetch, max_depth=2, max_links=50)
    assert links[0] == "http://test.local/"
    assert "http://test.local/profile?id=1" in links
    assert "http://test.local/about" in links


def test_crawl_excludes_external_domains(fetch):
    links = crawler.crawl("http://test.local/", fetch=fetch)
    assert all("evil.example.com" not in link for link in links)


def test_crawl_respects_max_links(fetch):
    links = crawler.crawl("http://test.local/", fetch=fetch, max_links=1)
    assert len(links) == 1


def test_crawl_handles_fetch_failure():
    links = crawler.crawl("http://down.local/", fetch=lambda url: None)
    assert links == ["http://down.local/"]


def test_same_domain_helpers():
    assert crawler.is_same_domain("http://a.test.local", "http://b.test.local")
    assert not crawler.is_same_domain("http://test.local", "http://other.com")
    assert crawler.get_root_domain("api.test.local:8080") == "test.local"
