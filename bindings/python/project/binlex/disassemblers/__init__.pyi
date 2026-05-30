from __future__ import annotations

from enum import Enum

from binlex.config import Configuration
from binlex.controlflow import Block, Function, Graph, Instruction
from binlex.core import Architecture
from binlex.formats import Image


class DisassemblerBackend(str, Enum):
    Default: str
    Capstone: str
    Native: str


class Disassembler:
    architecture: Architecture
    backend: DisassemblerBackend

    def __init__(
        self,
        architecture: Architecture,
        image: Image | bytes | memoryview,
        executable_address_ranges: dict[int, int],
        configuration: Configuration,
        backend: DisassemblerBackend = DisassemblerBackend.Default,
    ) -> None: ...
    def disassemble_instruction(self, address: int, graph: Graph) -> Instruction: ...
    def disassemble_function(self, address: int, graph: Graph) -> Function: ...
    def disassemble_block(self, address: int, graph: Graph) -> Block: ...
    def disassemble(self, addresses: set[int], graph: Graph) -> None: ...
    def disassemble_sweep(self) -> set[int]: ...


__all__: list[str]
