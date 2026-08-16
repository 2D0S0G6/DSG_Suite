"""Stage 4 - Unminify / unbundle.

Minified/bundled JavaScript is close to unreadable for both regex detectors and
an LLM.  This stage:

* beautifies source (``jsbeautifier`` when installed, otherwise a dependency-free
  fallback that reintroduces line breaks), and
* splits webpack-style bundles into their individual module bodies so each
  module becomes an independently retrievable unit downstream.
"""

from __future__ import annotations

import re
from typing import List

from .models import JSAsset

try:  # optional, nicer output when present
    import jsbeautifier  # type: ignore

    _HAS_JSBEAUTIFIER = True
except Exception:  # pragma: no cover - depends on optional dep
    _HAS_JSBEAUTIFIER = False


def _fallback_beautify(code: str) -> str:
    """Reintroduce newlines around statement/braces boundaries.

    Deliberately conservative: it never touches string/regex contents beyond
    splitting on the structural characters, which is enough to make dense
    single-line bundles greppable and chunkable.
    """
    out = re.sub(r";(?=\S)", ";\n", code)
    out = re.sub(r"\{(?=\S)", "{\n", out)
    out = re.sub(r"(?<=\S)\}", "\n}", out)
    return out


def beautify(code: str) -> str:
    if not code:
        return ""
    if _HAS_JSBEAUTIFIER:
        try:
            return jsbeautifier.beautify(code)
        except Exception:  # pragma: no cover - defensive
            pass
    return _fallback_beautify(code)


# Matches webpack module maps: `12: function(module, exports) { ... }` entries.
_MODULE_RE = re.compile(r"(\d+)\s*:\s*function\s*\(", re.MULTILINE)


def unbundle(code: str) -> List[str]:
    """Best-effort split of a bundle into module bodies.

    Returns a single-element list containing the whole source when no bundle
    structure is detected, so callers can treat the result uniformly.
    """
    matches = list(_MODULE_RE.finditer(code))
    if len(matches) < 2:
        return [code]

    modules: List[str] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(code)
        modules.append(code[start:end])
    return modules


def process(assets: List[JSAsset]) -> List[JSAsset]:
    """Beautify then unbundle every asset, preserving provenance in the URL."""
    processed: List[JSAsset] = []
    for asset in assets:
        pretty = beautify(asset.content)
        modules = unbundle(pretty)
        if len(modules) == 1:
            processed.append(
                JSAsset(url=asset.url, content=modules[0], inline=asset.inline)
            )
        else:
            for idx, module in enumerate(modules):
                processed.append(
                    JSAsset(
                        url=f"{asset.url}::module{idx}",
                        content=module,
                        inline=asset.inline,
                    )
                )
    return processed
