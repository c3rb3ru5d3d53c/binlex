from __future__ import annotations

from enum import Enum

from binlex import Architecture, Configuration
from binlex.controlflow import Block, Function, Instruction


class EmbeddingBackend(str, Enum):
    DEFAULT: EmbeddingBackend
    LLVM: EmbeddingBackend
    VEX: EmbeddingBackend


class Embedding:
    architecture: Architecture
    configuration: Configuration
    backend: EmbeddingBackend
    dimensions: int

    def __init__(
        self,
        architecture: Architecture,
        configuration: Configuration,
        backend: EmbeddingBackend = EmbeddingBackend.DEFAULT,
        dimensions: int = 64,
    ) -> None: ...

    def embed_instruction(self, instruction: Instruction) -> list[float] | None: ...
    def embed_block(self, block: Block) -> list[float] | None: ...
    def embed_function(self, function: Function) -> list[float] | None: ...


__all__: list[str]
