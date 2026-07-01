"""Rust-backed LIR bindings."""

from binlex_bindings.binlex.irs.lir import *
from binlex_bindings.binlex.irs.lir import LirBlock as _LirBlockBinding
from binlex_bindings.binlex.irs.lir import LirCpu as _LirCpuBinding
from binlex_bindings.binlex.irs.lir import LirData as _LirDataBinding
from binlex_bindings.binlex.irs.lir import LirExecutor as _LirExecutorBinding
from binlex_bindings.binlex.irs.lir import LirExecutorState as _LirExecutorStateBinding
from binlex_bindings.binlex.irs.lir import LirInstruction as _LirInstructionBinding
from binlex_bindings.binlex.irs.lir import LirFunction as _LirFunctionBinding
from binlex_bindings.binlex.irs.lir import LirMlirModule as _LirMlirModuleBinding
from binlex_bindings.binlex.irs.lir import LirModule as _LirModuleBinding
from binlex_bindings.binlex.irs.lir import LirPhiSource as _LirPhiSourceBinding

from binlex.core.architecture import Architecture


def _unwrap(value):
    return getattr(value, "_inner", value)


def _cpu_kind_from_architecture(architecture):
    if isinstance(architecture, Architecture):
        value = architecture.value
    else:
        value = str(architecture)
    if value == "amd64":
        return LirCpuKind.Amd64
    if value == "i386":
        return LirCpuKind.I386
    if value == "arm64":
        return LirCpuKind.Arm64
    if value == "cil":
        return LirCpuKind.Cil
    raise ValueError(f"unsupported architecture for lir cpu: {value}")


def _cpu_from_architecture(architecture):
    if isinstance(architecture, Architecture):
        value = architecture.value
    else:
        value = str(architecture)
    if value == "amd64":
        return LirCpuAmd64()
    if value == "i386":
        return LirCpuI386()
    if value == "arm64":
        return LirCpuArm64()
    if value == "cil":
        return LirCpuCil()
    raise ValueError(f"unsupported architecture for lir cpu: {value}")


class LirCpu:
    """Declarative CPU model for LIR and symbolic execution."""

    def __init__(
        self,
        *,
        name,
        address_bits,
        endian,
        registers=None,
        aliases=None,
        program_counter=None,
        memory=None,
    ):
        self._inner = _LirCpuBinding(
            name=name,
            address_bits=address_bits,
            endian=endian,
            registers=list(registers or []),
            aliases=list(aliases or []),
            program_counter=program_counter,
            memory=list(memory or []),
        )

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def name(self):
        return self._inner.name()

    def address_bits(self):
        return self._inner.address_bits()

    def endian(self):
        return self._inner.endian()

    def kind(self):
        return self._inner.kind()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirCpuI386(LirCpu):
    def __init__(self):
        self._inner = _LirCpuBinding.i386()


class LirCpuAmd64(LirCpu):
    def __init__(self):
        self._inner = _LirCpuBinding.amd64()


class LirCpuArm64(LirCpu):
    def __init__(self):
        self._inner = _LirCpuBinding.arm64()


class LirCpuCil(LirCpu):
    def __init__(self):
        self._inner = _LirCpuBinding.cil()


class _LirVariantWrapper:
    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def print(self):
        self._inner.print()

    def text(self):
        return self._inner.text()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirLocationRegister(_LirVariantWrapper):
    _binding = LirLocation

    def __init__(self, name, bits):
        self._inner = LirLocation.register(name, bits)


class LirLocationFlag(_LirVariantWrapper):
    _binding = LirLocation

    def __init__(self, name, bits):
        self._inner = LirLocation.flag(name, bits)


class LirLocationProgramCounter(_LirVariantWrapper):
    _binding = LirLocation

    def __init__(self, bits):
        self._inner = LirLocation.program_counter(bits)


class LirLocationTemporary(_LirVariantWrapper):
    _binding = LirLocation

    def __init__(self, id, bits):
        self._inner = LirLocation.temporary(id, bits)


class LirLocationMemory(_LirVariantWrapper):
    _binding = LirLocation

    def __init__(self, address_space, addr, bits):
        self._inner = LirLocation.memory(_unwrap(address_space), _unwrap(addr), bits)


class LirLocationIndexedMemory(_LirVariantWrapper):
    _binding = LirLocation

    def __init__(self, name, index, bits):
        self._inner = LirLocation.indexed_memory(name, _unwrap(index), bits)


class LirLocationStackMemory(_LirVariantWrapper):
    _binding = LirLocation

    def __init__(self, name, offset, bits):
        self._inner = LirLocation.stack_memory(name, offset, bits)


class LirExpressionConst(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, value, bits):
        self._inner = LirExpression.const(value, bits)


class LirExpressionFunction(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, name, bits):
        self._inner = LirExpression.function(name, bits)


class LirExpressionDataAddress(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, name, bits):
        self._inner = LirExpression.data_address(name, bits)


class LirExpressionAddressOf(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, location, bits):
        self._inner = LirExpression.address_of(_unwrap(location), bits)


class LirExpressionRead(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, location):
        self._inner = LirExpression.read(_unwrap(location))


class LirExpressionLoad(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, address_space, addr, bits):
        self._inner = LirExpression.load(_unwrap(address_space), _unwrap(addr), bits)


class LirExpressionUnary(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, op, arg, bits):
        self._inner = LirExpression.unary(_unwrap(op), _unwrap(arg), bits)


class LirExpressionBinary(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, op, left, right, bits):
        self._inner = LirExpression.binary(_unwrap(op), _unwrap(left), _unwrap(right), bits)


class LirExpressionCast(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, op, arg, bits):
        self._inner = LirExpression.cast(_unwrap(op), _unwrap(arg), bits)


class LirExpressionCompare(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, op, left, right, bits):
        self._inner = LirExpression.compare(_unwrap(op), _unwrap(left), _unwrap(right), bits)


class LirExpressionSelect(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, condition, when_true, when_false, bits):
        self._inner = LirExpression.select(
            _unwrap(condition),
            _unwrap(when_true),
            _unwrap(when_false),
            bits,
        )


class LirExpressionExtract(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, arg, lsb, bits):
        self._inner = LirExpression.extract(_unwrap(arg), lsb, bits)


class LirExpressionConcat(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, parts, bits):
        self._inner = LirExpression.concat([_unwrap(item) for item in list(parts or [])], bits)


class LirExpressionUndefined(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, bits):
        self._inner = LirExpression.undefined(bits)


class LirExpressionPoison(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, bits):
        self._inner = LirExpression.poison(bits)


class LirExpressionIntrinsic(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, name, args, bits):
        self._inner = LirExpression.intrinsic(name, [_unwrap(item) for item in list(args or [])], bits)


class LirExpressionNull(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, bits):
        self._inner = LirExpression.null(bits)


class LirExpressionAllocate(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, kind, bits):
        self._inner = LirExpression.allocate(kind, bits)


class LirExpressionReadProperty(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, reference, name, bits):
        self._inner = LirExpression.read_property(_unwrap(reference), name, bits)


class LirExpressionReadElement(_LirVariantWrapper):
    _binding = LirExpression

    def __init__(self, reference, index, bits):
        self._inner = LirExpression.read_element(_unwrap(reference), _unwrap(index), bits)


class LirEffectSet(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, dst, expression):
        self._inner = LirEffect.set(_unwrap(dst), _unwrap(expression))


class LirPhiSource:
    def __init__(self, value, predecessor=None):
        self._inner = _LirPhiSourceBinding(_unwrap(value), predecessor)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def predecessor(self):
        return self._inner.predecessor()

    def value(self):
        return LirExpression._from_inner(self._inner.value())

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirEffectPhi(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, dst, sources):
        self._inner = LirEffect.phi(_unwrap(dst), [_unwrap(item) for item in list(sources or [])])


class LirEffectStore(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, address_space, addr, expression, bits):
        self._inner = LirEffect.store(_unwrap(address_space), _unwrap(addr), _unwrap(expression), bits)


class LirEffectWriteProperty(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, reference, name, expression, bits):
        self._inner = LirEffect.write_property(_unwrap(reference), name, _unwrap(expression), bits)


class LirEffectWriteElement(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, reference, index, expression, bits):
        self._inner = LirEffect.write_element(
            _unwrap(reference),
            _unwrap(index),
            _unwrap(expression),
            bits,
        )


class LirEffectPush(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, stack, expression):
        self._inner = LirEffect.push(stack, _unwrap(expression))


class LirEffectPop(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, stack, dst):
        self._inner = LirEffect.pop(stack, _unwrap(dst))


class LirEffectFence(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, kind):
        self._inner = LirEffect.fence(_unwrap(kind))


class LirEffectTrap(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, kind):
        self._inner = LirEffect.trap(_unwrap(kind))


class LirEffectIntrinsic(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self, name, args=None, outputs=None):
        self._inner = LirEffect.intrinsic(
            name,
            [_unwrap(item) for item in list(args or [])],
            [_unwrap(item) for item in list(outputs or [])],
        )


class LirEffectNop(_LirVariantWrapper):
    _binding = LirEffect

    def __init__(self):
        self._inner = LirEffect.nop()


class LirTerminatorFallThrough(_LirVariantWrapper):
    _binding = LirTerminator

    def __init__(self):
        self._inner = LirTerminator.fallthrough()


class LirTerminatorJump(_LirVariantWrapper):
    _binding = LirTerminator

    def __init__(self, target):
        self._inner = LirTerminator.jump(_unwrap(target))


class LirTerminatorBranch(_LirVariantWrapper):
    _binding = LirTerminator

    def __init__(self, condition, true_target, false_target):
        self._inner = LirTerminator.branch(
            _unwrap(condition),
            _unwrap(true_target),
            _unwrap(false_target),
        )


class LirTerminatorCall(_LirVariantWrapper):
    _binding = LirTerminator

    def __init__(self, target, return_target=None, does_return=None):
        self._inner = LirTerminator.call(
            _unwrap(target),
            None if return_target is None else _unwrap(return_target),
            does_return,
        )


class LirTerminatorReturn(_LirVariantWrapper):
    _binding = LirTerminator

    def __init__(self, expression=None):
        self._inner = LirTerminator.return_(None if expression is None else _unwrap(expression))


class LirTerminatorUnreachable(_LirVariantWrapper):
    _binding = LirTerminator

    def __init__(self):
        self._inner = LirTerminator.unreachable()


class LirTerminatorTrap(_LirVariantWrapper):
    _binding = LirTerminator

    def __init__(self):
        self._inner = LirTerminator.trap()


class LirInstruction:
    """Wrapper around the Rust low-level instruction IR object."""

    def __init__(
        self,
        status,
        address=None,
        effects=None,
        terminator=None,
    ):
        effects = [_unwrap(item) for item in list(effects or [])]
        terminator = _unwrap(terminator) if terminator is not None else None
        self._inner = _LirInstructionBinding(
            status=status,
            address=address,
            effects=effects,
            terminator=terminator,
        )

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def text(self):
        return self._inner.text()

    def ssa(self):
        return LirInstruction._from_inner(self._inner.ssa())

    def bytecode(self):
        return self._inner.bytecode()

    def print(self):
        self._inner.print()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirMlirModule:
    """Wrapper around an MLIR-backed Rust LIR module object."""

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
        return cls._from_inner(_LirMlirModuleBinding.from_text(text))

    @classmethod
    def from_bytecode(cls, bytecode):
        return cls._from_inner(_LirMlirModuleBinding.from_bytecode(bytecode))

    def normalize_status(self):
        self._inner.normalize_status()

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


class LirExecutor:
    """Symbolically executes LIR modules and instructions."""

    def __init__(self):
        self._inner = _LirExecutorBinding()

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def step(self, lir, state):
        return [
            LirExecutorState._from_inner(item)
            for item in self._inner.step(_unwrap(lir), _unwrap(state))
        ]

    def run(self, lir, state, steps=None):
        return [
            LirExecutorState._from_inner(item)
            for item in self._inner.run(_unwrap(lir), _unwrap(state), steps)
        ]

    def run_with_hooks(self, lir, state, steps=None):
        return [
            LirExecutorState._from_inner(item)
            for item in self._inner.run_with_hooks(_unwrap(lir), _unwrap(state), steps)
        ]

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirExecutorState:
    """CPU and memory state used by LIR symbolic execution."""

    def __init__(self, cpu):
        self._inner = _LirExecutorStateBinding(_unwrap(cpu))

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirData:
    """Named static data attached to an LIR module."""

    def __init__(self, name, bytes):
        self._inner = _LirDataBinding(name=name, bytes=bytes)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirBlock:
    """Block-scoped container for low-level instructions."""

    def __init__(self, name=None):
        self._inner = _LirBlockBinding(name=name)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def instructions(self):
        return [LirInstruction._from_inner(item) for item in self._inner.instructions()]

    def append_instruction(self, instruction):
        instruction = getattr(instruction, "_inner", instruction)
        self._inner.append_instruction(instruction)

    def text(self):
        return self._inner.text()

    def ssa(self):
        return LirBlock._from_inner(self._inner.ssa())

    def bytecode(self):
        return self._inner.bytecode()

    def print(self):
        self._inner.print()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirFunction:
    """Function-scoped low-level IR."""

    def __init__(self, name=None):
        self._inner = _LirFunctionBinding(name=name)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def blocks(self):
        return [LirBlock._from_inner(item) for item in self._inner.blocks()]

    def append_block(self, block):
        block = getattr(block, "_inner", block)
        self._inner.append_block(block)

    def text(self):
        return self._inner.text()

    def ssa(self):
        return LirFunction._from_inner(self._inner.ssa())

    def bytecode(self):
        return self._inner.bytecode()

    def print(self):
        self._inner.print()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirModule:
    """Module-scoped low-level IR."""

    def __init__(self, name=None):
        self._inner = _LirModuleBinding(name=name)
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

    def from_text(cls, text):
        return cls._from_mlir_inner(_LirModuleBinding.from_text(text))

    @classmethod
    def from_bytecode(cls, bytecode):
        return cls._from_mlir_inner(_LirModuleBinding.from_bytecode(bytecode))

    def functions(self):
        return [LirFunction._from_inner(item) for item in self._inner.functions()]

    def data(self):
        return [LirData._from_inner(item) for item in self._inner.data()]

    def append_function(self, function):
        function = getattr(function, "_inner", function)
        self._inner.append_function(function)

    def append_data(self, data):
        data = getattr(data, "_inner", data)
        self._inner.append_data(data)

    def text(self):
        if self._mlir:
            return self._inner.text()
        return self._inner.text()

    def ssa(self):
        if self._mlir:
            raise TypeError("MLIR-backed LIR modules do not support SSA rewriting")
        return LirModule._from_inner(self._inner.ssa())

    def bytecode(self):
        return self._inner.bytecode()

    def mlir(self):
        if self._mlir:
            return LirMlirModule._from_inner(self._inner)
        return LirMlirModule._from_inner(self._inner.mlir())

    def operation_names(self):
        return self.mlir().operation_names()

    def operation_count(self):
        return self.mlir().operation_count()

    def operation_records(self):
        return self.mlir().operation_records()

    def print(self):
        self._inner.print()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)
