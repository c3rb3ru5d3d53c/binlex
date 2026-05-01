"""Rust-backed symbolic execution bindings."""

from binlex_bindings.binlex.symbolic import Executor as _ExecutorBinding
from binlex_bindings.binlex.symbolic import State

from binlex.core.architecture import _coerce_architecture


class Executor:
    """Execute Binlex semantics symbolically."""

    def __init__(self, architecture):
        self._inner = _ExecutorBinding(_coerce_architecture(architecture))

    def state(self):
        return self._inner.state()

    def step(self, semantics, state):
        return self._inner.step(semantics, state)

    def run(self, semantics, state):
        return self._inner.run(semantics, state)

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = ["Executor", "State"]
