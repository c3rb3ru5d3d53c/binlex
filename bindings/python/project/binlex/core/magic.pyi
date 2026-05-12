from __future__ import annotations

from typing import ClassVar, Literal, TypeAlias

from binlex_bindings.binlex.core.magic import Magic as _MagicBinding

MagicValue: TypeAlias = Literal["code", "pe", "coff", "elf", "macho", "png", "unknown"]

class Magic(str):
    CODE: ClassVar[Magic]
    PE: ClassVar[Magic]
    COFF: ClassVar[Magic]
    ELF: ClassVar[Magic]
    MACHO: ClassVar[Magic]
    PNG: ClassVar[Magic]
    UNKNOWN: ClassVar[Magic]
    def __new__(cls, data: MagicValue | bytes | bytearray | memoryview | _MagicBinding) -> Magic: ...
    @property
    def value(self) -> str: ...
    def to_binding(self) -> _MagicBinding: ...
    @classmethod
    def from_binding(cls, magic: _MagicBinding) -> Magic: ...

def _coerce_magic(magic: Magic | _MagicBinding) -> _MagicBinding: ...

__all__ = ["Magic", "_coerce_magic"]
