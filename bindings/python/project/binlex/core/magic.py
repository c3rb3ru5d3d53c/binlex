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

"""File-type detection helpers for the Python bindings."""

from __future__ import annotations

from typing import ClassVar

from binlex_bindings.binlex.core.magic import Magic as _MagicBinding


class Magic(str):
    """Known file kinds returned by binlex type detection helpers."""

    _VALID_NAMES: ClassVar[frozenset[str]] = frozenset(
        {"code", "pe", "elf", "macho", "png", "unknown"}
    )

    CODE: ClassVar["Magic"]
    PE: ClassVar["Magic"]
    ELF: ClassVar["Magic"]
    MACHO: ClassVar["Magic"]
    PNG: ClassVar["Magic"]
    UNKNOWN: ClassVar["Magic"]

    def __new__(cls, data: str | bytes | bytearray | memoryview | _MagicBinding) -> "Magic":
        normalized = cls._normalize(data)
        return str.__new__(cls, normalized)

    @property
    def value(self) -> str:
        """Return the canonical string value for this magic kind."""
        return str(self)

    def to_binding(self) -> _MagicBinding:
        """Convert the value into the underlying native binding enum."""
        return _MagicBinding.from_string(self.value)

    @classmethod
    def from_binding(cls, magic: _MagicBinding) -> "Magic":
        """Convert a native binding enum into the Python `Magic` value."""
        return cls(magic)

    @classmethod
    def _normalize(cls, data: str | bytes | bytearray | memoryview | _MagicBinding) -> str:
        if isinstance(data, _MagicBinding):
            normalized = str(data)
        elif isinstance(data, (bytes, bytearray, memoryview)):
            normalized = str(_MagicBinding(bytes(data)))
        elif isinstance(data, str):
            normalized = data.lower()
        else:
            raise TypeError(f"unsupported magic data: {data!r}")

        if normalized not in cls._VALID_NAMES:
            raise ValueError(f"invalid magic data: {data!r}")
        return normalized


Magic.CODE = Magic("code")
Magic.PE = Magic("pe")
Magic.ELF = Magic("elf")
Magic.MACHO = Magic("macho")
Magic.PNG = Magic("png")
Magic.UNKNOWN = Magic("unknown")


def _coerce_magic(magic: Magic | _MagicBinding) -> _MagicBinding:
    """Normalize Python and native magic values into the native representation."""
    if isinstance(magic, Magic):
        return magic.to_binding()
    return magic


__all__ = ["Magic", "_coerce_magic"]
