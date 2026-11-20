"""Alias and query normalization for exact catalogue matching (spec §8, §7.4).

Matching is deterministic and case-insensitive. Punctuation is collapsed so that
"Visual Studio Code", "visual-studio-code" and "visual studio code" resolve the same way.
"""

from __future__ import annotations

import re
import unicodedata

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_MULTI_SPACE = re.compile(r"\s+")


def normalize_alias(raw: str) -> str:
    """Lowercase, strip accents, replace non-alphanumerics with spaces, collapse spaces."""
    text = unicodedata.normalize("NFKD", raw)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.casefold().strip()
    text = _NON_ALNUM.sub(" ", text)
    return _MULTI_SPACE.sub(" ", text).strip()


def slug_candidate(raw: str) -> str:
    """Turn free text into a slug-shaped token used as a secondary lookup key."""
    return normalize_alias(raw).replace(" ", "-")
