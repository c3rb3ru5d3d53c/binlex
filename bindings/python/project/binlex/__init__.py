# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Public Python entrypoints for the binlex bindings.

The `binlex` package re-exports the primary enums, configuration objects,
and higher-level subpackages that wrap the compiled Rust extension.
"""

from importlib import import_module

from .clients import Server, Web
from .config import Config
from .core import Architecture, Magic

_LAZY_SUBMODULES = {
    "clients",
    "compression",
    "controlflow",
    "disassemblers",
    "formats",
    "genetics",
    "hashing",
    "hex",
    "indexing",
    "databases",
    "lifters",
    "math",
    "metadata",
    "storage",
    "util",
    "yara",
}


def __getattr__(name):
    """Load Python wrapper subpackages on first access."""
    if name in _LAZY_SUBMODULES:
        module = import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "Architecture",
    "Config",
    "Magic",
    "Server",
    "Web",
    "clients",
    "compression",
    "controlflow",
    "disassemblers",
    "formats",
    "genetics",
    "hashing",
    "hex",
    "indexing",
    "databases",
    "lifters",
    "math",
    "metadata",
    "storage",
    "util",
    "yara",
]
