"""Compare dotted OS/app version strings without accepting arbitrary expressions.

Only digit-and-dot segments are compared (e.g. ``26.5``, ``1.138.0``). Pre-release
labels and non-numeric garbage make the comparison fail closed.
"""

from __future__ import annotations

import re

_VERSION = re.compile(r"^\d+(?:\.\d+){0,5}$")


def parse_version(raw: str) -> tuple[int, ...] | None:
    text = raw.strip()
    if not _VERSION.fullmatch(text):
        return None
    parts = tuple(int(p) for p in text.split("."))
    if any(p < 0 or p > 99_999 for p in parts):
        return None
    return parts


def meets_minimum(actual: str, minimum: str) -> bool | None:
    """Return True/False when both versions parse, else None (fail closed for callers)."""
    left, right = parse_version(actual), parse_version(minimum)
    if left is None or right is None:
        return None
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return padded_left >= padded_right
