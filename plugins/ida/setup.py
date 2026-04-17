from __future__ import annotations

import re
from pathlib import Path

from setuptools import setup


def cargo_workspace_version() -> str:
    for base in [Path(__file__).resolve().parent, *Path(__file__).resolve().parents]:
        cargo_toml = base / "Cargo.toml"
        if not cargo_toml.is_file():
            continue
        content = cargo_toml.read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^\[workspace\.package\]\s+.*?^version\s*=\s*\"([^\"]+)\"",
            content,
        )
        if match is not None:
            return match.group(1)

    pkg_info = Path(__file__).resolve().parent / "PKG-INFO"
    if pkg_info.is_file():
        content = pkg_info.read_text(encoding="utf-8")
        match = re.search(r"(?m)^Version:\s*(.+)\s*$", content)
        if match is not None:
            return match.group(1).strip()

    raise RuntimeError("could not determine package version from Cargo.toml or PKG-INFO")


setup(version=cargo_workspace_version())
