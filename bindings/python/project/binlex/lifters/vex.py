"""VEX lifter wrappers backed by the Rust core implementation."""

from binlex_bindings.binlex.lifters.vex import Lifter as _LifterBinding


class Lifter:
    """Lift instructions, blocks, and functions into VEX IR artifacts."""

    def __init__(self, config, _inner=None):
        self._config = config
        self._inner = _LifterBinding(config) if _inner is None else _inner

    def lift_instruction(self, instruction):
        if self._inner.lift_instruction(instruction._inner):
            return self
        return None

    def lift_block(self, block):
        if self._inner.lift_block(block._inner):
            return self
        return None

    def lift_function(self, function):
        if self._inner.lift_function(function._inner):
            return self
        return None

    def text(self):
        return self._inner.text()

    def print(self):
        return self._inner.print()

    def __str__(self):
        return self.text()


__all__ = ["Lifter"]
