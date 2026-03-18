from __future__ import annotations

from enum import Enum

class Magic(str, Enum):
    CODE: Magic
    PE: Magic
    ELF: Magic
    MACHO: Magic
    PNG: Magic
    UNKNOWN: Magic
    @classmethod
    def from_file(cls, path: str) -> Magic: ...
    @classmethod
    def from_bytes(cls, bytes: bytes) -> Magic: ...

__all__ = ["Magic"]
