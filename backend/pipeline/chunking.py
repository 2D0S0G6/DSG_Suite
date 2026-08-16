"""Stage 5 - Chunk / context generation.

Breaks JS assets, HTML pages and endpoints into overlapping, size-bounded
:class:`Chunk` objects.  Overlap preserves context that would otherwise be split
across a boundary (e.g. a sink and the variable feeding it).
"""

from __future__ import annotations

from typing import Dict, List

from .models import Chunk, Endpoint, JSAsset


def _window(text: str, size: int, overlap: int) -> List[str]:
    if size <= 0:
        return [text]
    step = max(1, size - overlap)
    windows: List[str] = []
    for start in range(0, max(1, len(text)), step):
        piece = text[start : start + size]
        if piece:
            windows.append(piece)
        if start + size >= len(text):
            break
    return windows


def chunk_js(
    assets: List[JSAsset], size: int = 1200, overlap: int = 150
) -> List[Chunk]:
    chunks: List[Chunk] = []
    for a_idx, asset in enumerate(assets):
        for w_idx, window in enumerate(_window(asset.content, size, overlap)):
            chunks.append(
                Chunk(
                    id=f"js-{a_idx}-{w_idx}",
                    source=asset.url,
                    kind="js",
                    content=window,
                    metadata={"inline": asset.inline},
                )
            )
    return chunks


def chunk_html(pages: Dict[str, str], size: int = 1200, overlap: int = 150) -> List[Chunk]:
    chunks: List[Chunk] = []
    for p_idx, (url, html) in enumerate(pages.items()):
        for w_idx, window in enumerate(_window(html or "", size, overlap)):
            chunks.append(
                Chunk(
                    id=f"html-{p_idx}-{w_idx}",
                    source=url,
                    kind="html",
                    content=window,
                )
            )
    return chunks


def chunk_endpoints(endpoints: List[Endpoint]) -> List[Chunk]:
    chunks: List[Chunk] = []
    for idx, ep in enumerate(endpoints):
        content = f"{ep.method} {ep.url}\nparameters: {', '.join(ep.params) or 'none'}"
        chunks.append(
            Chunk(
                id=f"endpoint-{idx}",
                source=ep.url,
                kind="endpoint",
                content=content,
                metadata={"method": ep.method, "params": ep.params},
            )
        )
    return chunks


def build_chunks(
    assets: List[JSAsset],
    pages: Dict[str, str],
    endpoints: List[Endpoint],
    size: int = 1200,
    overlap: int = 150,
) -> List[Chunk]:
    """Produce the full corpus of retrievable context for the RAG stage."""
    return (
        chunk_js(assets, size, overlap)
        + chunk_html(pages, size, overlap)
        + chunk_endpoints(endpoints)
    )
