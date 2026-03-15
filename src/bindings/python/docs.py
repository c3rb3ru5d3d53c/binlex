#!/usr/bin/env python3
"""Build Python API documentation into the local ``docs/`` directory."""

from __future__ import annotations

import argparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import subprocess
import sys


IGNORED_PREFIXES = (
    "Warn: Error parsing type annotation ",
)

DEFAULT_ARGS = [
    "--docformat",
    "google",
    "--no-show-source",
    "--output-directory",
    "docs",
    "binlex",
    "!binlex.disassemblers.ida",
]


def _validate_cwd() -> None:
    cwd = Path.cwd().resolve()
    expected_files = (
        cwd / "pyproject.toml",
        cwd / "project" / "binlex" / "__init__.py",
    )
    if all(path.exists() for path in expected_files):
        return

    raise SystemExit(
        "python -m docs must be run from src/bindings/python/ after activating "
        "a virtual environment with the docs dependencies installed."
    )


def _parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        prog="python -m docs",
        description="Build the Python API documentation.",
        add_help=True,
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Serve the generated docs on localhost after building.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to use with --serve. Defaults to 8000.",
    )
    return parser.parse_known_args(argv)


def _build_docs(args: list[str]) -> int:
    pdoc_args = DEFAULT_ARGS if len(args) == 0 else args
    process = subprocess.run(
        [sys.executable, "-m", "pdoc", *pdoc_args],
        capture_output=True,
        text=True,
    )

    if process.stdout:
        sys.stdout.write(process.stdout)

    if process.stderr:
        for line in process.stderr.splitlines(True):
            if line.startswith(IGNORED_PREFIXES):
                continue
            sys.stderr.write(line)

    return process.returncode


def _serve_docs(port: int) -> int:
    docs_dir = Path.cwd() / "docs"
    if not docs_dir.exists():
        raise SystemExit("The docs directory was not generated.")

    class DocsHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(docs_dir), **kwargs)

    address = ("127.0.0.1", port)
    print(f"Serving docs at http://127.0.0.1:{port}")
    with ThreadingHTTPServer(address, DocsHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 0


def main(argv: list[str] | None = None) -> int:
    _validate_cwd()
    known_args, pdoc_args = _parse_args([] if argv is None else argv)
    result = _build_docs(pdoc_args)
    if result != 0:
        return result
    if known_args.serve:
        return _serve_docs(known_args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
