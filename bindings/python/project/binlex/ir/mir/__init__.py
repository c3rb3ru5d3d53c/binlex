"""Rust-backed MIR bindings."""

from importlib import import_module

_mir = import_module("binlex_bindings.binlex.ir.mir")

MirAddressSpace = _mir.MirAddressSpace
MirBlock = _mir.MirBlock
MirBlockParameter = _mir.MirBlockParameter
MirCastOp = _mir.MirCastOp
MirCompareOp = _mir.MirCompareOp
MirOperation = _mir.MirOperation
MirTerminator = _mir.MirTerminator
MirType = _mir.MirType
MirValue = _mir.MirValue
_MirFunctionBinding = _mir.MirFunction
_MirModuleBinding = _mir.MirModule
MirTypeKind = getattr(_mir, "MirTypeKind", None)
MirTerminatorKind = getattr(_mir, "MirTerminatorKind", None)


class MirFunction:
    """Wrapper around a Rust MIR function object."""

    def __init__(self, name=None):
        self._inner = _MirFunctionBinding(name=name)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_MirFunctionBinding.from_dict(data))

    @classmethod
    def from_lir(cls, lir_function, name=None):
        lir_function = getattr(lir_function, "_inner", lir_function)
        return cls._from_inner(_MirFunctionBinding.from_lir(lir_function, name=name))

    def append_block(self, block):
        block = getattr(block, "_inner", block)
        self._inner.append_block(block)

    def blocks(self):
        return self._inner.blocks()

    def verify(self):
        return self._inner.verify()

    def optimize_register_state(self):
        self._inner.optimize_register_state()

    def optimize_returns(self):
        self._inner.optimize_returns()

    def optimize_blocks(self):
        self._inner.optimize_blocks()

    def optimize_abi(self):
        self._inner.optimize_abi()

    def optimize_subexpressions(self):
        self._inner.optimize_subexpressions()

    def optimize_flags(self):
        self._inner.optimize_flags()

    def optimize_liveness(self):
        self._inner.optimize_liveness()

    def optimize_undefs(self):
        self._inner.optimize_undefs()

    def optimize_intrinsics(self):
        self._inner.optimize_intrinsics()

    def optimize_cse(self):
        self._inner.optimize_cse()

    def optimize_stack(self):
        self._inner.optimize_stack()

    def optimize_stack_pointers(self):
        self._inner.optimize_stack_pointers()

    def optimize_stack_slots(self):
        self._inner.optimize_stack_slots()

    def optimize_calls(self):
        self._inner.optimize_calls()

    def optimize_call_clobbers(self):
        self._inner.optimize_call_clobbers()

    def optimize_memory_aliases(self):
        self._inner.optimize_memory_aliases()

    def optimize_branches(self):
        self._inner.optimize_branches()

    def optimize_memory_state(self):
        self._inner.optimize_memory_state()

    def optimize_constants(self):
        self._inner.optimize_constants()

    def optimize_dead_effects(self):
        self._inner.optimize_dead_effects()

    def optimize_copy_propagation(self):
        self._inner.optimize_copy_propagation()

    def optimize_targets(self):
        self._inner.optimize_targets()

    def optimize_ssa(self):
        self._inner.optimize_ssa()

    def optimize_ssa_liveness(self):
        self._inner.optimize_ssa_liveness()

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

    def __getattr__(self, name):
        return getattr(self._inner, name)


class MirModule:
    """Wrapper around a Rust MIR module object."""

    def __init__(self, name=None):
        self._inner = _MirModuleBinding(name=name)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_MirModuleBinding.from_dict(data))

    @classmethod
    def from_lir(cls, lir_module, name=None):
        lir_module = getattr(lir_module, "_inner", lir_module)
        return cls._from_inner(_MirModuleBinding.from_lir(lir_module, name=name))

    def append_function(self, function):
        function = getattr(function, "_inner", function)
        self._inner.append_function(function)

    def functions(self):
        return self._inner.functions()

    def verify(self):
        return self._inner.verify()

    def optimize_register_state(self):
        self._inner.optimize_register_state()

    def optimize_returns(self):
        self._inner.optimize_returns()

    def optimize_blocks(self):
        self._inner.optimize_blocks()

    def optimize_abi(self):
        self._inner.optimize_abi()

    def optimize_subexpressions(self):
        self._inner.optimize_subexpressions()

    def optimize_flags(self):
        self._inner.optimize_flags()

    def optimize_liveness(self):
        self._inner.optimize_liveness()

    def optimize_undefs(self):
        self._inner.optimize_undefs()

    def optimize_intrinsics(self):
        self._inner.optimize_intrinsics()

    def optimize_cse(self):
        self._inner.optimize_cse()

    def optimize_stack(self):
        self._inner.optimize_stack()

    def optimize_stack_pointers(self):
        self._inner.optimize_stack_pointers()

    def optimize_stack_slots(self):
        self._inner.optimize_stack_slots()

    def optimize_calls(self):
        self._inner.optimize_calls()

    def optimize_call_clobbers(self):
        self._inner.optimize_call_clobbers()

    def optimize_memory_aliases(self):
        self._inner.optimize_memory_aliases()

    def optimize_branches(self):
        self._inner.optimize_branches()

    def optimize_memory_state(self):
        self._inner.optimize_memory_state()

    def optimize_constants(self):
        self._inner.optimize_constants()

    def optimize_dead_effects(self):
        self._inner.optimize_dead_effects()

    def optimize_copy_propagation(self):
        self._inner.optimize_copy_propagation()

    def optimize_targets(self):
        self._inner.optimize_targets()

    def optimize_ssa(self):
        self._inner.optimize_ssa()

    def optimize_ssa_liveness(self):
        self._inner.optimize_ssa_liveness()

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

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = [
    "MirFunction",
    "MirModule",
    "MirAddressSpace",
    "MirBlock",
    "MirBlockParameter",
    "MirCastOp",
    "MirCompareOp",
    "MirOperation",
    "MirTerminator",
    "MirType",
    "MirValue",
]

if MirTypeKind is not None:
    __all__.append("MirTypeKind")

if MirTerminatorKind is not None:
    __all__.append("MirTerminatorKind")
