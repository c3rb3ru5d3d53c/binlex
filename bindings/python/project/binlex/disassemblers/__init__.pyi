from __future__ import annotations

from enum import Enum

from binlex.controlflow import Block, Function, Graph, Instruction
from binlex.core import Architecture


class DisassemblerBackend(str, Enum):
    Default: str
    Capstone: str
    Native: str


class Disassembler:
    architecture: Architecture
    backend: DisassemblerBackend

    def __init__(
        self,
        graph: Graph,
        backend: DisassemblerBackend = DisassemblerBackend.Default,
    ) -> None: ...
    def disassemble_instruction(self, address: int) -> Instruction: ...
    def disassemble_function(self, address: int) -> Function: ...
    def disassemble_block(self, address: int) -> Block: ...
    def disassemble(self, addresses: set[int]) -> None: ...
    def disassemble_sweep(self) -> set[int]: ...


__all__: list[str]
