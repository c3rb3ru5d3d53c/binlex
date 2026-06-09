"""Graph-scoped decompilation orchestration."""

from __future__ import annotations

from enum import Enum

from binlex_bindings.binlex.decompilers import Decompiler as _DecompilerBinding


class DecompilerBackend(str, Enum):
    DEFAULT = "default"


class Decompiler:
    """Coordinate staged decompilation over a graph."""

    def __init__(self, graph, backend=DecompilerBackend.DEFAULT):
        if not isinstance(backend, DecompilerBackend):
            raise TypeError("backend must be a DecompilerBackend")
        self._graph = graph
        self._backend = backend
        self._graph._decompiler = self
        self._inner = _DecompilerBinding(
            graph._inner,
            backend.value,
        )

    @property
    def graph(self):
        return self._graph

    @property
    def image(self):
        return self._graph.image()

    @property
    def configuration(self):
        return self._graph.configuration()

    @property
    def backend(self):
        return self._backend

    def function(self, address):
        return self._graph.function(address)

    def decompile_function(self, address):
        if self._inner.decompile_function(address) is None:
            return None
        return self._graph.function(address)

    def decompile(self):
        self._inner.decompile()
        return self

__all__ = ["Decompiler", "DecompilerBackend"]
