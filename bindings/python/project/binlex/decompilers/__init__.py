"""Graph-scoped decompilation orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import os

from binlex.config import Configuration


class DecompilerBackend(str, Enum):
    DEFAULT = "default"


class Decompiler:
    """Coordinate staged decompilation over a graph."""

    def __init__(self, graph, configuration, symbols=None, backend=DecompilerBackend.DEFAULT):
        if not isinstance(backend, DecompilerBackend):
            raise TypeError("backend must be a DecompilerBackend")
        if not isinstance(configuration, Configuration):
            raise TypeError("configuration must be a Configuration")
        self._graph = graph
        self._configuration = configuration
        self._symbols = [] if symbols is None else [_freeze_symbol(symbol) for symbol in symbols]
        self._backend = backend
        self._graph._decompiler = self
        self._graph._decompilation_cache = {"lir": {}, "mir": {}, "hir": {}}
        self._symbol_address_map = None

    @property
    def graph(self):
        return self._graph

    @property
    def configuration(self):
        return self._configuration

    @property
    def symbols(self):
        return list(self._symbols)

    @property
    def backend(self):
        return self._backend

    def function(self, address):
        return self._graph.function(address)

    def decompile_function(self, address):
        function = self._graph.function(address)
        if function is None:
            return None
        self._decompile_function(function)
        return function

    def decompile(self):
        functions = self._graph.functions()
        worker_count = max(1, os.cpu_count() or 1)
        if self._configuration.threads > 0:
            worker_count = self._configuration.threads
        if worker_count <= 1 or len(functions) <= 1:
            for function in functions:
                self._decompile_function(function)
            return self

        target_batches = max(1, worker_count * 4)
        chunk_size = max(1, (len(functions) + target_batches - 1) // target_batches)
        batches = [functions[index:index + chunk_size] for index in range(0, len(functions), chunk_size)]
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            list(executor.map(self._decompile_batch, batches))
        return self

    def _decompile_function(self, function):
        if self._backend != DecompilerBackend.DEFAULT:
            raise ValueError(f"unsupported decompiler backend: {self._backend!r}")
        function.lir()
        function.mir()
        return function

    def _decompile_batch(self, functions):
        for function in functions:
            self._decompile_function(function)
        return functions

__all__ = ["Decompiler", "DecompilerBackend"]


def _freeze_symbol(symbol):
    if isinstance(symbol, dict):
        return dict(symbol)
    return {
        "name": symbol.name(),
        "virtual_address": symbol.virtual_address(),
        "relative_virtual_address": symbol.relative_virtual_address(),
        "kind": str(symbol.kind()),
    }
