from pipeline import chunking
from pipeline.models import Endpoint, JSAsset


def test_window_overlap_covers_full_text():
    chunks = chunking.chunk_js(
        [JSAsset(url="http://x/a.js", content="abcdefghij" * 30)],
        size=100,
        overlap=20,
    )
    assert len(chunks) > 1
    # overlap means consecutive chunks share a suffix/prefix
    assert chunks[0].content[-20:] == chunks[1].content[:20]


def test_chunk_kinds_are_labelled():
    js = chunking.chunk_js([JSAsset(url="http://x/a.js", content="x")])
    html = chunking.chunk_html({"http://x/": "<html></html>"})
    eps = chunking.chunk_endpoints([Endpoint(url="http://x/api", params=["id"])])
    assert js[0].kind == "js"
    assert html[0].kind == "html"
    assert eps[0].kind == "endpoint"
    assert "id" in eps[0].content


def test_build_chunks_combines_sources():
    chunks = chunking.build_chunks(
        [JSAsset(url="http://x/a.js", content="code")],
        {"http://x/": "<html></html>"},
        [Endpoint(url="http://x/api")],
    )
    kinds = {c.kind for c in chunks}
    assert kinds == {"js", "html", "endpoint"}
