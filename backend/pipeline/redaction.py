"""Secret redaction — the last boundary before anything reaches the model.

Every evidence form and every chunk of collected client-side data passes through
:func:`redact` before it is handed to Groq.  Tokens, keys, cookies and obvious
PII are replaced with ``[REDACTED:kind]`` placeholders.

Redaction is *lossy on purpose* for the model, but it still records **that** a
secret existed and **where** (:func:`scan_secrets`), so a "hardcoded secret"
finding can be reported without the raw value ever leaving the process.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

# (kind, pattern) — order matters: match the most specific first.  Patterns are
# intentionally conservative to avoid shredding ordinary code.
_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9\-_\.=]{16,}")),
    (
        "api_key",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|access[_-]?token|client[_-]?secret|password|passwd)\b"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9\-_\.]{8,})['\"]?"
        ),
    ),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b")),
    ("groq_key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b")),
    ("slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("hex_secret", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
]


def scan_secrets(text: str) -> List[Dict[str, str]]:
    """Return metadata about secrets present in ``text`` (no raw values).

    Each entry is ``{"kind": ..., "hint": <first/last 2 chars>}`` so a finding can
    point at a real secret without exposing it.
    """
    hits: List[Dict[str, str]] = []
    if not text:
        return hits
    for kind, pattern in _PATTERNS:
        if kind == "email":  # emails are PII, not "hardcoded secrets" worth flagging
            continue
        for m in pattern.finditer(text):
            raw = m.group(0)
            hint = f"{raw[:2]}…{raw[-2:]}" if len(raw) > 6 else "…"
            hits.append({"kind": kind, "hint": hint})
    return hits


def redact(text: str) -> str:
    """Replace secrets/PII in ``text`` with ``[REDACTED:kind]`` placeholders."""
    if not text:
        return text
    out = text
    for kind, pattern in _PATTERNS:
        out = pattern.sub(f"[REDACTED:{kind}]", out)
    return out


def redact_obj(obj):
    """Recursively redact all string values in a JSON-like structure."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
