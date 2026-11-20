"""Unit tests for catalogue ingest helpers (no DB)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.catalogue.ingest import _safe_filename, load_store_pins, pin_digest
from app.core.errors import AppError


def test_safe_filename_accepts_pkg() -> None:
    assert _safe_filename("go1.25.4.pkg") == "go1.25.4.pkg"


def test_safe_filename_rejects_non_pkg() -> None:
    with pytest.raises(AppError):
        _safe_filename("evil.exe")
    with pytest.raises(AppError):
        _safe_filename("bad name.pkg")


def test_pin_and_load_store_pins(tmp_path: Path) -> None:
    store = tmp_path / "packages"
    settings = SimpleNamespace(package_store_dir=str(store))
    digest = "a" * 64
    pin_digest(settings, digest)  # type: ignore[arg-type]
    pin_digest(settings, digest)  # type: ignore[arg-type]
    assert load_store_pins(settings) == {digest}  # type: ignore[arg-type]
