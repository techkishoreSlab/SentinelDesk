"""Unit tests for Phase 9 ops helpers."""

from __future__ import annotations

from app.ops.retention import summarize


def test_summarize_orders_keys() -> None:
    assert summarize({"b": 1, "a": 2}) == "a=2, b=1"
