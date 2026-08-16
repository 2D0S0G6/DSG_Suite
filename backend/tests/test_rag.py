from pipeline.models import Chunk
from pipeline.rag import TfidfRetriever, tokenize


def _corpus():
    return [
        Chunk(id="1", source="a", kind="js", content="element.innerHTML = userInput dangerous sink"),
        Chunk(id="2", source="b", kind="js", content="const total = price * quantity accounting"),
        Chunk(id="3", source="c", kind="js", content="var api_key = 'secret token credentials'"),
    ]


def test_tokenize_drops_short_and_punct():
    # single-character tokens (a, x) are dropped as noise
    assert tokenize("a.b_c innerHTML=x") == ["b_c", "innerhtml"]


def test_retrieval_ranks_relevant_chunk_first():
    r = TfidfRetriever().fit(_corpus())
    top = r.retrieve("innerHTML sink dangerous", top_k=1)
    assert top and top[0].id == "1"


def test_retrieval_for_secrets():
    r = TfidfRetriever().fit(_corpus())
    top = r.retrieve("api_key secret credentials", top_k=1)
    assert top[0].id == "3"


def test_empty_index_returns_nothing():
    assert TfidfRetriever().fit([]).retrieve("anything") == []


def test_query_scores_are_bounded():
    r = TfidfRetriever().fit(_corpus())
    for _, score in r.query("innerHTML", top_k=3):
        assert 0.0 <= score <= 1.0 + 1e-9
