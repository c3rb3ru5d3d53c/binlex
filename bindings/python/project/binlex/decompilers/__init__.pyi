from __future__ import annotations

from enum import Enum

from binlex.controlflow import Function, Graph
from binlex.formats import Image
from binlex.config import Configuration


class DecompilerBackend(str, Enum):
    DEFAULT: str

class Decompiler:
    def __init__(
        self,
        graph: Graph,
        backend: DecompilerBackend = DecompilerBackend.DEFAULT,
    ) -> None: ...
    @property
    def graph(self) -> Graph: ...
    @property
    def image(self) -> Image: ...
    @property
    def configuration(self) -> Configuration: ...
    @property
    def backend(self) -> DecompilerBackend: ...
    def function(self, address: int) -> Function | None: ...
    def decompile_function(self, address: int) -> Function | None: ...
    def decompile(self) -> Decompiler: ...

__all__: list[str]
