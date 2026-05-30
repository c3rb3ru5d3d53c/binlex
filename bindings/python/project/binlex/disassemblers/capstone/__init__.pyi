from __future__ import annotations

from binlex import Architecture, Configuration
from binlex.controlflow import Block, Function, Graph, Instruction
from binlex.formats import Image

class Disassembler:
    def __init__(
        self,
        machine: Architecture,
        image: Image | bytes,
        executable_address_ranges: dict[int, int],
        configuration: Configuration,
    ) -> None: ...
    def disassemble_instruction(self, address: int, graph: Graph) -> Instruction: ...
    def disassemble_function(self, address: int, graph: Graph) -> Function: ...
    def disassemble_block(self, address: int, graph: Graph) -> Block: ...
    def disassemble(self, addresses: set[int], graph: Graph) -> None: ...
    def disassemble_sweep(self) -> set[int]: ...

__all__: list[str]
