from __future__ import annotations

from enum import Enum

from binlex import Config
from binlex.core import Architecture


class AssemblerBackend(str, Enum):
    Default: AssemblerBackend
    LLVM: AssemblerBackend


class Assembler:
    def __init__(
        self,
        architecture: Architecture,
        config: Config,
        backend: AssemblerBackend = AssemblerBackend.Default,
    ) -> None: ...
    def assemble(self, address: int, text: str) -> bytes: ...


__all__: list[str]
