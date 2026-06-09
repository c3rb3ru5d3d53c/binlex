"""Graph-scoped decompilation orchestration."""

from __future__ import annotations

from enum import Enum

from binlex_bindings.binlex.decompilers import Decompiler as _DecompilerBinding

from binlex.irs.hir import HirFunction
from binlex.irs.ast import AstFunction
from binlex.irs.lir import LirFunction
from binlex.irs.mir import MirFunction


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
        self._graph._decompilation_cache = {"lir": {}, "mir": {}, "hir": {}, "ast": {}}
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

    def _cache_lir(self, address, lir):
        lir = LirFunction._from_inner(lir)
        self._graph._decompilation_cache["lir"][address] = lir
        return lir

    def _cache_mir(self, address, mir):
        mir = MirFunction._from_inner(mir)
        self._graph._decompilation_cache["mir"][address] = mir
        return mir

    def _cache_hir(self, address, hir):
        hir = HirFunction._from_inner(hir)
        self._graph._decompilation_cache["hir"][address] = hir
        return hir

    def _cache_ast(self, address, ast):
        ast = AstFunction._from_inner(ast)
        self._graph._decompilation_cache["ast"][address] = ast
        return ast

    def _cache_artifacts(self, address, lir, mir, hir, ast):
        self._cache_lir(address, lir)
        self._cache_mir(address, mir)
        self._cache_hir(address, hir)
        self._cache_ast(address, ast)

    def decompile_function(self, address):
        result = self._inner.decompile_function_artifacts(address)
        if result is None:
            return None
        lir, mir, hir, ast = result
        self._cache_artifacts(address, lir, mir, hir, ast)
        return self._graph.function(address)

    def decompile(self):
        for address, lir, mir, hir, ast in self._inner.decompile_artifacts():
            self._cache_artifacts(address, lir, mir, hir, ast)
        return self

__all__ = ["Decompiler", "DecompilerBackend"]
