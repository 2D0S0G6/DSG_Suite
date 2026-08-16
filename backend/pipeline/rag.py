"""Stage 6 - RAG (retrieval).

A dependency-free TF-IDF + cosine-similarity retriever over the chunk corpus.
The LLM-analysis stage queries it per vulnerability class so only the most
relevant context is sent to the model (retrieval-augmented generation), keeping
prompts small and focused instead of dumping an entire minified bundle.

Pure Python on purpose: no numpy / faiss / embedding service, so it runs
deterministically in CI with zero external state.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Tuple

from .models import Chunk

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")


def tokenize(text: str) -> List[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "")]


class TfidfRetriever:
    """Fit on a chunk corpus, then retrieve the top-k chunks for a query."""

    def __init__(self) -> None:
        self.chunks: List[Chunk] = []
        self._doc_vectors: List[dict] = []
        self._idf: dict = {}

    def fit(self, chunks: List[Chunk]) -> "TfidfRetriever":
        self.chunks = list(chunks)
        n = len(self.chunks)
        doc_freq: Counter = Counter()
        tokenized: List[List[str]] = []

        for chunk in self.chunks:
            tokens = tokenize(chunk.content)
            tokenized.append(tokens)
            for term in set(tokens):
                doc_freq[term] += 1

        # Smoothed idf so a term present in every doc still carries weight > 0.
        self._idf = {
            term: math.log((1 + n) / (1 + df)) + 1.0 for term, df in doc_freq.items()
        }
        self._doc_vectors = [self._vectorize(tokens) for tokens in tokenized]
        return self

    def _vectorize(self, tokens: List[str]) -> dict:
        counts = Counter(tokens)
        total = sum(counts.values()) or 1
        vec = {
            term: (count / total) * self._idf.get(term, 0.0)
            for term, count in counts.items()
        }
        return vec

    @staticmethod
    def _cosine(a: dict, b: dict) -> float:
        if not a or not b:
            return 0.0
        # Iterate the smaller vector for the dot product.
        small, large = (a, b) if len(a) <= len(b) else (b, a)
        dot = sum(weight * large.get(term, 0.0) for term, weight in small.items())
        if dot == 0.0:
            return 0.0
        norm_a = math.sqrt(sum(w * w for w in a.values()))
        norm_b = math.sqrt(sum(w * w for w in b.values()))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def query(self, text: str, top_k: int = 6) -> List[Tuple[Chunk, float]]:
        if not self.chunks:
            return []
        q_vec = self._vectorize(tokenize(text))
        scored = [
            (chunk, self._cosine(q_vec, self._doc_vectors[i]))
            for i, chunk in enumerate(self.chunks)
        ]
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return [pair for pair in scored[:top_k] if pair[1] > 0]

    def retrieve(self, text: str, top_k: int = 6) -> List[Chunk]:
        return [chunk for chunk, _ in self.query(text, top_k)]
