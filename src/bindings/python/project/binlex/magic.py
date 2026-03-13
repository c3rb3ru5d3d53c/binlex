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

from enum import Enum

from binlex_bindings.binlex import Magic as _MagicBinding


class Magic(str, Enum):
    CODE = "code"
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    PNG = "png"
    UNKNOWN = "unknown"

    def to_binding(self) -> _MagicBinding:
        return _MagicBinding.from_string(self.value)

    @classmethod
    def from_binding(cls, magic: _MagicBinding) -> "Magic":
        return cls(str(magic))

    @classmethod
    def from_file(cls, path: str) -> "Magic":
        return cls.from_binding(_MagicBinding.from_file(path))

    @classmethod
    def from_bytes(cls, bytes: bytes) -> "Magic":
        return cls.from_binding(_MagicBinding.from_bytes(bytes))


def _coerce_magic(magic: Magic | _MagicBinding) -> _MagicBinding:
    if isinstance(magic, Magic):
        return magic.to_binding()
    return magic


__all__ = ["Magic"]
