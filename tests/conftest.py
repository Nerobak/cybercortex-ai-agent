"""Keep executable demonstration scripts out of pytest collection."""

from __future__ import annotations

from pathlib import Path


def pytest_ignore_collect(collection_path: Path, config) -> bool:
    del config
    if collection_path.suffix != ".py" or not collection_path.name.startswith("test_"):
        return False
    try:
        source = collection_path.read_text(encoding="utf-8")
    except OSError:
        return False
    return "def test_" not in source
