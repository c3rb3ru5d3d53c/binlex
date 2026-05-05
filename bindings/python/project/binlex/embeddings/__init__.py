"""Embedding interfaces for converting controlflow entities into vectors."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from binlex_bindings.binlex.embeddings import Embedding as _EmbeddingBinding

from binlex.core import Architecture
from binlex.core.architecture import _coerce_architecture

if TYPE_CHECKING:
    from binlex import Configuration
    from binlex.controlflow import Block, Function, Instruction


class EmbeddingBackend(str, Enum):
    DEFAULT = "default"
    LLVM = "llvm"
    VEX = "vex"


def _resolve_backend(backend: EmbeddingBackend) -> EmbeddingBackend:
    if not isinstance(backend, EmbeddingBackend):
        raise TypeError("backend must be an EmbeddingBackend")
    return backend


class Embedding:
    """Configured embedding service for controlflow entities."""

    def __init__(
        self,
        architecture: Architecture,
        configuration: Configuration,
        backend: EmbeddingBackend = EmbeddingBackend.DEFAULT,
        dimensions: int = 64,
    ) -> None:
        if dimensions < 1:
            raise ValueError("dimensions must be at least 1")
        self.architecture = Architecture.from_binding(_coerce_architecture(architecture))
        self.configuration = configuration
        self.backend = _resolve_backend(backend)
        self.dimensions = dimensions
        self._inner = _EmbeddingBinding(
            _coerce_architecture(architecture),
            configuration,
            self.backend,
            dimensions,
        )

    def embed_instruction(self, instruction: Instruction) -> list[float] | None:
        return self._inner.embed_instruction(instruction._inner)

    def embed_block(self, block: Block) -> list[float] | None:
        return self._inner.embed_block(block._inner)

    def embed_function(self, function: Function) -> list[float] | None:
        return self._inner.embed_function(function._inner)


__all__ = ["Embedding", "EmbeddingBackend"]
