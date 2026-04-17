from __future__ import annotations

import re
from pathlib import Path

from setuptools import setup


def cargo_workspace_version() -> str:
    cargo_toml = Path(__file__).resolve().parents[2] / "Cargo.toml"
    content = cargo_toml.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^\[workspace\.package\]\s+.*?^version\s*=\s*\"([^\"]+)\"",
        content,
    )
    if match is None:
        raise RuntimeError("could not determine workspace.package.version from Cargo.toml")
    return match.group(1)


setup(version=cargo_workspace_version())
