from __future__ import annotations

from collections.abc import Mapping, Set

from binlex import Architecture, Config
from binlex.controlflow import Graph
from binlex.formats import Image

class Disassembler:
    def __init__(
        self,
        machine: Architecture,
        image: Image | bytes,
        executable_address_ranges: dict[int, int],
        config: Config,
    ) -> None: ...
    def disassemble_instruction(self, address: int, cfg: Graph) -> int: ...
    def disassemble_function(self, address: int, cfg: Graph) -> int: ...
    def disassemble_block(self, address: int, cfg: Graph) -> int: ...
    def disassemble_controlflow(self, addresses: set[int], cfg: Graph) -> None: ...
    def disassemble_sweep(self) -> set[int]: ...

__all__: list[str]
