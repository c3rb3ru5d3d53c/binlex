"""Rust-backed symbolic execution bindings."""

from binlex_bindings.binlex.symbolic import Executor as _ExecutorBinding
from binlex_bindings.binlex.symbolic import Slice
from binlex_bindings.binlex.symbolic import SliceInstruction
from binlex_bindings.binlex.symbolic import SliceNode
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

    def run(self, semantics, state, steps=None):
        return self._inner.run(semantics, state, steps)

    def add_hook(self, address, hook):
        return self._inner.add_hook(address, hook)

    def remove_hook(self, address):
        return self._inner.remove_hook(address)

    def clear_hooks(self):
        return self._inner.clear_hooks()

    def hooks(self):
        return self._inner.hooks()

    def __getattr__(self, name):
        return getattr(self._inner, name)

__all__ = ["Executor", "Slice", "SliceInstruction", "SliceNode", "State"]
