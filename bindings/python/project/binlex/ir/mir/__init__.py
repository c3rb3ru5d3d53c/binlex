"""Rust-backed MIR bindings."""

from importlib import import_module

_mir = import_module("binlex_bindings.binlex.ir.mir")

MirAddressSpace = _mir.MirAddressSpace
_MirBlockBinding = _mir.MirBlock
MirBlockParameter = _mir.MirBlockParameter
MirCastOp = _mir.MirCastOp
MirCompareOp = _mir.MirCompareOp
MirOperation = _mir.MirOperation
MirTerminator = _mir.MirTerminator
MirType = _mir.MirType
MirStructureMember = _mir.MirStructureMember
MirUnionMember = _mir.MirUnionMember
MirValue = _mir.MirValue
_MirFunctionBinding = _mir.MirFunction
_MirModuleBinding = _mir.MirModule
_MirMlirModuleBinding = _mir.MirMlirModule
MirTypeKind = getattr(_mir, "MirTypeKind", None)
MirTerminatorKind = getattr(_mir, "MirTerminatorKind", None)


def _unwrap(value):
    return getattr(value, "_inner", value)


class _MirVariantWrapper:
    def to_dict(self):
        return self._inner.to_dict()

    def json(self):
        return self._inner.json()

    def __str__(self):
        return self.json()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class MirVoid(_MirVariantWrapper):
    def __init__(self):
        self._inner = MirType.void()


class MirInteger(_MirVariantWrapper):
    def __init__(self, bits):
        self._inner = MirType.integer(bits)


class MirFloat(_MirVariantWrapper):
    def __init__(self, bits):
        self._inner = MirType.float(bits)


class MirPointer(_MirVariantWrapper):
    def __init__(self, pointee):
        self._inner = MirType.pointer(_unwrap(pointee))


class MirMemory(_MirVariantWrapper):
    def __init__(self):
        self._inner = MirType.memory()


class MirTypeDefinition(_MirVariantWrapper):
    def __init__(self, name):
        self._inner = MirType.type_definition(name)


class MirStructure(_MirVariantWrapper):
    def __init__(self, name, members=None):
        self._inner = MirType.structure(name, [_unwrap(item) for item in list(members or [])])


class MirUnion(_MirVariantWrapper):
    def __init__(self, name, members=None):
        self._inner = MirType.union(name, [_unwrap(item) for item in list(members or [])])


class MirNamedValue(_MirVariantWrapper):
    def __init__(self, name, ty):
        self._inner = MirValue.named(name, _unwrap(ty))


class MirIntegerValue(_MirVariantWrapper):
    def __init__(self, value, bits):
        self._inner = MirValue.integer(value, bits)


class MirBooleanValue(_MirVariantWrapper):
    def __init__(self, value):
        self._inner = MirValue.boolean(value)


class MirNullValue(_MirVariantWrapper):
    def __init__(self, ty):
        self._inner = MirValue.null(_unwrap(ty))


class MirUndefValue(_MirVariantWrapper):
    def __init__(self, ty):
        self._inner = MirValue.undef(_unwrap(ty))


class MirCopyOperation(_MirVariantWrapper):
    def __init__(self, value, ty, result=None):
        self._inner = MirOperation.copy(_unwrap(value), _unwrap(ty), result=result)


class MirAddOperation(_MirVariantWrapper):
    def __init__(self, lhs, rhs, ty, result=None):
        self._inner = MirOperation.add(_unwrap(lhs), _unwrap(rhs), _unwrap(ty), result=result)


class MirSubOperation(_MirVariantWrapper):
    def __init__(self, lhs, rhs, ty, result=None):
        self._inner = MirOperation.sub(_unwrap(lhs), _unwrap(rhs), _unwrap(ty), result=result)


class MirMulOperation(_MirVariantWrapper):
    def __init__(self, lhs, rhs, ty, result=None):
        self._inner = MirOperation.mul(_unwrap(lhs), _unwrap(rhs), _unwrap(ty), result=result)


class MirLoadOperation(_MirVariantWrapper):
    def __init__(self, address_space, address, ty, result=None):
        self._inner = MirOperation.load(_unwrap(address_space), _unwrap(address), _unwrap(ty), result=result)


class MirStoreOperation(_MirVariantWrapper):
    def __init__(self, address_space, address, value, ty, result=None):
        self._inner = MirOperation.store(
            _unwrap(address_space),
            _unwrap(address),
            _unwrap(value),
            _unwrap(ty),
            result=result,
        )


class MirCompareOperation(_MirVariantWrapper):
    def __init__(self, op, lhs, rhs, ty, result=None):
        self._inner = MirOperation.icmp(_unwrap(op), _unwrap(lhs), _unwrap(rhs), _unwrap(ty), result=result)


class MirCastOperation(_MirVariantWrapper):
    def __init__(self, op, value, ty, result=None):
        self._inner = MirOperation.cast(_unwrap(op), _unwrap(value), _unwrap(ty), result=result)


class MirCallOperation(_MirVariantWrapper):
    def __init__(self, target, arguments=None, result_types=None, result=None):
        self._inner = MirOperation.call(
            target,
            [_unwrap(item) for item in list(arguments or [])],
            [_unwrap(item) for item in list(result_types or [])],
            result=result,
        )


class MirIntrinsicOperation(_MirVariantWrapper):
    def __init__(self, name, arguments=None, result_types=None, result=None):
        self._inner = MirOperation.intrinsic(
            name,
            [_unwrap(item) for item in list(arguments or [])],
            [_unwrap(item) for item in list(result_types or [])],
            result=result,
        )


class MirJumpTerminator(_MirVariantWrapper):
    def __init__(self, target, arguments=None):
        self._inner = MirTerminator.jump(target, [_unwrap(item) for item in list(arguments or [])])


class MirCondBrTerminator(_MirVariantWrapper):
    def __init__(
        self,
        condition,
        then_target,
        else_target,
        then_arguments=None,
        else_arguments=None,
    ):
        self._inner = MirTerminator.cond_br(
            _unwrap(condition),
            then_target,
            else_target,
            [_unwrap(item) for item in list(then_arguments or [])],
            [_unwrap(item) for item in list(else_arguments or [])],
        )


class MirReturnTerminator(_MirVariantWrapper):
    def __init__(self, values=None):
        self._inner = MirTerminator.return_([_unwrap(item) for item in list(values or [])])


class MirTrapTerminator(_MirVariantWrapper):
    def __init__(self):
        self._inner = MirTerminator.trap()


class MirUnreachableTerminator(_MirVariantWrapper):
    def __init__(self):
        self._inner = MirTerminator.unreachable()


class MirBlock:
    def __init__(self, name):
        self._inner = _MirBlockBinding(name)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_lir(cls, lir_block, name=None):
        return cls._from_inner(_MirBlockBinding.from_lir(_unwrap(lir_block), name=name))

    def append_parameter(self, parameter):
        self._inner.append_parameter(_unwrap(parameter))

    def append_operation(self, operation):
        self._inner.append_operation(_unwrap(operation))

    def set_terminator(self, terminator):
        self._inner.set_terminator(_unwrap(terminator))

    def name(self):
        return self._inner.name()

    def json(self):
        return self._inner.json()

    def to_dict(self):
        return self._inner.to_dict()

    def __getattr__(self, name):
        return getattr(self._inner, name)


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
        block = _unwrap(block)
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
        self._mlir = False

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        instance._mlir = False
        return instance

    @classmethod
    def _from_mlir_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        instance._mlir = True
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_MirModuleBinding.from_dict(data))

    @classmethod
    def from_lir(cls, lir_module, name=None):
        lir_module = getattr(lir_module, "_inner", lir_module)
        return cls._from_inner(_MirModuleBinding.from_lir(lir_module, name=name))

    @classmethod
    def from_text(cls, text):
        return cls._from_mlir_inner(_MirModuleBinding.from_text(text))

    @classmethod
    def from_bytecode(cls, bytecode):
        return cls._from_mlir_inner(_MirModuleBinding.from_bytecode(bytecode))

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
        if self._mlir:
            self._inner.optimize()
            return
        self._inner.optimize()

    def text(self):
        if self._mlir:
            return self._inner.text()
        return self._inner.text()

    def bytecode(self):
        return self._inner.bytecode()

    def mlir(self):
        if self._mlir:
            return MirMlirModule._from_inner(self._inner)
        return MirMlirModule._from_inner(self._inner.mlir())

    def operation_names(self):
        return self.mlir().operation_names()

    def operation_count(self):
        return self.mlir().operation_count()

    def operation_records(self):
        return self.mlir().operation_records()

    def print(self):
        self._inner.print()

    def json(self):
        return self._inner.json()

    def to_dict(self):
        return self._inner.to_dict()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class MirMlirModule:
    """Wrapper around an MLIR-backed Rust MIR module object."""

    def __init__(self, module):
        module = getattr(module, "_inner", module)
        self._inner = module.mlir()

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_text(cls, text):
        return cls._from_inner(_MirMlirModuleBinding.from_text(text))

    @classmethod
    def from_bytecode(cls, bytecode):
        return cls._from_inner(_MirMlirModuleBinding.from_bytecode(bytecode))

    def optimize_copy_propagation(self):
        self._inner.optimize_copy_propagation()

    def optimize_constants(self):
        self._inner.optimize_constants()

    def optimize(self):
        self._inner.optimize()

    def text(self):
        return self._inner.text()

    def bytecode(self):
        return self._inner.bytecode()

    def operation_names(self):
        return self._inner.operation_names()

    def operation_count(self):
        return self._inner.operation_count()

    def operation_records(self):
        return self._inner.operation_records()

    def print(self):
        self._inner.print()

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = [
    "MirFunction",
    "MirModule",
    "MirMlirModule",
    "MirAddressSpace",
    "MirBlock",
    "MirBlockParameter",
    "MirCastOp",
    "MirCompareOp",
    "MirOperation",
    "MirCopyOperation",
    "MirTerminator",
    "MirType",
    "MirStructureMember",
    "MirUnionMember",
    "MirValue",
]

if MirTypeKind is not None:
    __all__.append("MirTypeKind")

if MirTerminatorKind is not None:
    __all__.append("MirTerminatorKind")
