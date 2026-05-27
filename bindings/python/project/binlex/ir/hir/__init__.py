"""Rust-backed HIR bindings."""

from importlib import import_module

_hir = import_module("binlex_bindings.binlex.ir.hir")

HirBlock = _hir.HirBlock
HirExpression = _hir.HirExpression
HirStatement = _hir.HirStatement
HirValue = _hir.HirValue
_HirFunctionBinding = _hir.HirFunction
_HirModuleBinding = _hir.HirModule


class HirFunction:
    """Wrapper around a Rust HIR function object."""

    def __init__(self, name=None):
        self._inner = _HirFunctionBinding(name=name)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_HirFunctionBinding.from_dict(data))

    @classmethod
    def from_mir(cls, mir_function, name=None):
        mir_function = getattr(mir_function, "_inner", mir_function)
        return cls._from_inner(_HirFunctionBinding.from_mir(mir_function, name=name))

    @classmethod
    def from_lir(cls, lir_function, name=None):
        lir_function = getattr(lir_function, "_inner", lir_function)
        return cls._from_inner(_HirFunctionBinding.from_lir(lir_function, name=name))

    def append_block(self, block):
        block = getattr(block, "_inner", block)
        self._inner.append_block(block)

    def blocks(self):
        return self._inner.blocks()

    def verify(self):
        return self._inner.verify()

    def optimize_inline_temps(self):
        self._inner.optimize_inline_temps()

    def optimize_algebraic(self):
        self._inner.optimize_algebraic()

    def optimize_condition_idioms(self):
        self._inner.optimize_condition_idioms()

    def optimize_boolean(self):
        self._inner.optimize_boolean()

    def optimize_load_hoisting(self):
        self._inner.optimize_load_hoisting()

    def optimize_call_arguments(self):
        self._inner.optimize_call_arguments()

    def optimize_memory_forms(self):
        self._inner.optimize_memory_forms()

    def optimize_pointer_reads(self):
        self._inner.optimize_pointer_reads()

    def optimize_cfg(self):
        self._inner.optimize_cfg()

    def optimize_locals(self):
        self._inner.optimize_locals()

    def optimize(self):
        self._inner.optimize()

    def text(self):
        return self._inner.text()

    def print(self):
        self._inner.print()

    def json(self):
        return self._inner.json()

    def to_dict(self):
        return self._inner.to_dict()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class HirModule:
    """Wrapper around a Rust HIR module object."""

    def __init__(self, name=None):
        self._inner = _HirModuleBinding(name=name)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_HirModuleBinding.from_dict(data))

    @classmethod
    def from_mir(cls, mir_module, name=None):
        mir_module = getattr(mir_module, "_inner", mir_module)
        return cls._from_inner(_HirModuleBinding.from_mir(mir_module, name=name))

    @classmethod
    def from_lir(cls, lir_module, name=None):
        lir_module = getattr(lir_module, "_inner", lir_module)
        return cls._from_inner(_HirModuleBinding.from_lir(lir_module, name=name))

    def append_function(self, function):
        function = getattr(function, "_inner", function)
        self._inner.append_function(function)

    def functions(self):
        return self._inner.functions()

    def verify(self):
        return self._inner.verify()

    def optimize_inline_temps(self):
        self._inner.optimize_inline_temps()

    def optimize_algebraic(self):
        self._inner.optimize_algebraic()

    def optimize_condition_idioms(self):
        self._inner.optimize_condition_idioms()

    def optimize_boolean(self):
        self._inner.optimize_boolean()

    def optimize_load_hoisting(self):
        self._inner.optimize_load_hoisting()

    def optimize_call_arguments(self):
        self._inner.optimize_call_arguments()

    def optimize_memory_forms(self):
        self._inner.optimize_memory_forms()

    def optimize_pointer_reads(self):
        self._inner.optimize_pointer_reads()

    def optimize_cfg(self):
        self._inner.optimize_cfg()

    def optimize_locals(self):
        self._inner.optimize_locals()

    def optimize(self):
        self._inner.optimize()

    def text(self):
        return self._inner.text()

    def print(self):
        self._inner.print()

    def json(self):
        return self._inner.json()

    def to_dict(self):
        return self._inner.to_dict()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = [
    "HirFunction",
    "HirModule",
    "HirBlock",
    "HirExpression",
    "HirStatement",
    "HirValue",
]
