from __future__ import annotations

from collections.abc import Mapping, Sequence

from binlex import Architecture, Configuration
from binlex.controlflow import Block, Function, Graph, Instruction
from binlex.formats import Image, Symbol


class Disassembler:
    def __init__(
        self,
        machine: Architecture,
        image: Image | bytes | memoryview,
        executable_address_ranges: dict[int, int],
        configuration: Configuration,
        symbols: Sequence[Symbol | Mapping[str, object]] | None = None,
    ) -> None: ...
    def disassemble_instruction(self, address: int, graph: Graph) -> Instruction: ...
    def disassemble_function(self, address: int, graph: Graph) -> Function: ...
    def disassemble_block(self, address: int, graph: Graph) -> Block: ...
    def disassemble(self, addresses: set[int], graph: Graph) -> None: ...


__all__: list[str]
