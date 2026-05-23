"""Graph-scoped decompilation orchestration."""

from __future__ import annotations

from enum import Enum

from binlex_bindings.binlex.decompilers import Decompiler as _DecompilerBinding

from binlex.config import Configuration
from binlex.ir.lir import LirFunction
from binlex.ir.mir import MirFunction


class DecompilerBackend(str, Enum):
    DEFAULT = "default"


class Decompiler:
    """Coordinate staged decompilation over a graph."""

    def __init__(self, graph, configuration, backend=DecompilerBackend.DEFAULT):
        if not isinstance(backend, DecompilerBackend):
            raise TypeError("backend must be a DecompilerBackend")
        if not isinstance(configuration, Configuration):
            raise TypeError("configuration must be a Configuration")
        self._graph = graph
        self._configuration = configuration
        self._backend = backend
        self._graph._decompiler = self
        self._graph._decompilation_cache = {"lir": {}, "mir": {}, "hir": {}}
        self._inner = _DecompilerBinding(graph._inner, configuration, backend.value)

    @property
    def graph(self):
        return self._graph

    @property
    def configuration(self):
        return self._configuration

    @property
    def backend(self):
        return self._backend

    def function(self, address):
        return self._graph.function(address)

    def _cache_lir(self, address, lir):
        lir = LirFunction._from_inner(lir)
        if self._configuration.decompiler.lir.optimize.enabled:
            setattr(lir, "_binlex_decompiler_lir_optimized", True)
        self._graph._decompilation_cache["lir"][address] = lir
        return lir

    def _cache_mir(self, address, mir):
        mir = MirFunction._from_inner(mir)
        if self._configuration.decompiler.mir.optimize.enabled:
            setattr(mir, "_binlex_decompiler_mir_optimized", True)
        self._graph._decompilation_cache["mir"][address] = mir
        return mir

    def _cache_artifacts(self, address, lir, mir):
        self._cache_lir(address, lir)
        self._cache_mir(address, mir)

    def decompile_function(self, address):
        result = self._inner.decompile_function_artifacts(address)
        if result is None:
            return None
        lir, mir = result
        self._cache_artifacts(address, lir, mir)
        return self._graph.function(address)

    def decompile(self):
        for address, lir, mir in self._inner.decompile_artifacts():
            self._cache_artifacts(address, lir, mir)
        return self

__all__ = ["Decompiler", "DecompilerBackend"]
