"""VEX IR module wrappers backed by the Rust core implementation."""

from binlex_bindings.binlex.irs.vex import VexBlock as _VexBlockBinding
from binlex_bindings.binlex.irs.vex import VexFunction as _VexFunctionBinding
from binlex_bindings.binlex.irs.vex import VexModule as _VexModuleBinding
from binlex_bindings.binlex.irs.vex import VexStatement as _VexStatementBinding


class VexModule:
    """Module-scoped VEX IR."""

    def __init__(self, name=None, _inner=None, _config=None):
        self._config = _config
        self._inner = _VexModuleBinding(name) if _inner is None else _inner

    @classmethod
    def _from_inner(cls, inner, config=None):
        return cls(_inner=inner, _config=config)

    @classmethod
    def _with_config(cls, name, config):
        return cls._from_inner(_VexModuleBinding.with_config(name, config), config)

    def from_lir(self, module, config):
        if self._inner.from_lir(module._inner, config):
            self._config = config
            return self
        return None

    def name(self):
        return self._inner.name()

    def functions(self):
        return [VexFunction._from_inner(function) for function in self._inner.functions()]

    def append_function(self, function):
        function = getattr(function, "_inner", function)
        self._inner.append_function(function)
        return self

    def clear(self):
        if self._inner.clear():
            return self
        return None

    def text(self):
        return self._inner.text()

    def print(self):
        return self._inner.print()

    def __str__(self):
        return self.text()


class VexFunction:
    """Function-scoped VEX IR."""

    def __init__(self, name=None, _inner=None):
        self._inner = _VexFunctionBinding(name) if _inner is None else _inner

    @classmethod
    def _from_inner(cls, inner):
        return cls(_inner=inner)

    def name(self):
        return self._inner.name()

    def blocks(self):
        return [VexBlock._from_inner(block) for block in self._inner.blocks()]

    def append_block(self, block):
        block = getattr(block, "_inner", block)
        self._inner.append_block(block)
        return self

    def text(self):
        return self._inner.text()

    def print(self):
        return self._inner.print()

    def __str__(self):
        return self.text()


class VexBlock:
    """Block-scoped VEX IR."""

    def __init__(self, name=None, _inner=None):
        self._inner = _VexBlockBinding(name) if _inner is None else _inner

    @classmethod
    def _from_inner(cls, inner):
        return cls(_inner=inner)

    def name(self):
        return self._inner.name()

    def statements(self):
        return [VexStatement._from_inner(statement) for statement in self._inner.statements()]

    def append_statement(self, statement):
        statement = getattr(statement, "_inner", statement)
        self._inner.append_statement(statement)
        return self

    def text(self):
        return self._inner.text()

    def print(self):
        return self._inner.print()

    def __str__(self):
        return self.text()


class VexStatement:
    """Single VEX statement."""

    def __init__(self, text, _inner=None):
        self._inner = _VexStatementBinding(text) if _inner is None else _inner

    @classmethod
    def _from_inner(cls, inner):
        return cls(None, _inner=inner)

    def text(self):
        return self._inner.text()

    def print(self):
        return self._inner.print()

    def __str__(self):
        return self.text()


__all__ = ["VexModule", "VexFunction", "VexBlock", "VexStatement"]
