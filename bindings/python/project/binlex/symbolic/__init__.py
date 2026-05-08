"""Rust-backed symbolic execution bindings."""

from binlex_bindings.binlex.symbolic import SymbolicExecutor as _SymbolicExecutorBinding
from binlex_bindings.binlex.symbolic import Slice
from binlex_bindings.binlex.symbolic import SliceInstruction
from binlex_bindings.binlex.symbolic import SliceNode
from binlex_bindings.binlex.symbolic import SymbolicCpuState as _SymbolicCpuStateBinding

from binlex.semantics import SemanticCpu


class SymbolicCpuState:
    """Symbolic state for a specific semantic CPU model."""

    def __init__(self, cpu):
        if isinstance(cpu, SemanticCpu):
            cpu = cpu._inner
        self._inner = _SymbolicCpuStateBinding(cpu)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def __getattr__(self, name):
        return getattr(self._inner, name)


class SymbolicExecutor:
    """Execute Binlex semantics symbolically."""

    def __init__(self):
        self._inner = _SymbolicExecutorBinding()

    def step(self, semantics, state):
        states = self._inner.step(semantics, state._inner)
        return [SymbolicCpuState._from_inner(state) for state in states]

    def run(self, semantics, state, steps=None):
        states = self._inner.run(semantics, state._inner, steps)
        return [SymbolicCpuState._from_inner(state) for state in states]

    def add_hook(self, address, hook):
        def native_hook(hook_address, native_state):
            state = SymbolicCpuState._from_inner(native_state)
            return [returned._inner for returned in hook(hook_address, state)]

        return self._inner.add_hook(address, native_hook)

    def remove_hook(self, address):
        return self._inner.remove_hook(address)

    def clear_hooks(self):
        return self._inner.clear_hooks()

    def hooks(self):
        return self._inner.hooks()

    def __getattr__(self, name):
        return getattr(self._inner, name)

__all__ = [
    "SymbolicExecutor",
    "Slice",
    "SliceInstruction",
    "SliceNode",
    "SymbolicCpuState",
]
