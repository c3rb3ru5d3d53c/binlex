"""Rust-backed LIR bindings."""

from binlex_bindings.binlex.ir.lir import *
from binlex_bindings.binlex.ir.lir import LirAbi as _LirAbiBinding
from binlex_bindings.binlex.ir.lir import LirBlock as _LirBlockBinding
from binlex_bindings.binlex.ir.lir import LirCpu as _LirCpuBinding
from binlex_bindings.binlex.ir.lir import LirData as _LirDataBinding
from binlex_bindings.binlex.ir.lir import LirExecutor as _LirExecutorBinding
from binlex_bindings.binlex.ir.lir import LirExecutorState as _LirExecutorStateBinding
from binlex_bindings.binlex.ir.lir import Lir as _LirBinding
from binlex_bindings.binlex.ir.lir import LirFunction as _LirFunctionBinding
from binlex_bindings.binlex.ir.lir import LirMlirModule as _LirMlirModuleBinding
from binlex_bindings.binlex.ir.lir import LirModule as _LirModuleBinding

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

    @classmethod
    def from_kind(cls, kind):
        if isinstance(kind, Architecture) or str(kind) in {"amd64", "i386", "arm64", "cil"}:
            kind = _cpu_kind_from_architecture(kind)
        return cls._from_inner(_LirCpuBinding.from_kind(kind))

    @classmethod
    def from_architecture(cls, architecture):
        return cls.from_kind(_cpu_kind_from_architecture(architecture))

    @classmethod
    def i386(cls):
        return cls._from_inner(_LirCpuBinding.i386())

    @classmethod
    def amd64(cls):
        return cls._from_inner(_LirCpuBinding.amd64())

    @classmethod
    def arm64(cls):
        return cls._from_inner(_LirCpuBinding.arm64())

    @classmethod
    def cil(cls):
        return cls._from_inner(_LirCpuBinding.cil())

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


class LirAbi:
    """Declarative ABI model for LIR and lifting."""

    def __init__(
        self,
        *,
        name,
        cpu,
        function_arguments=None,
        return_locations=None,
        function_return_bits=None,
        traps=None,
    ):
        cpu = getattr(cpu, "_inner", cpu)
        self._inner = _LirAbiBinding(
            name=name,
            cpu=cpu,
            function_arguments=list(function_arguments or []),
            return_locations=list(return_locations or []),
            function_return_bits=function_return_bits,
            traps=list(traps or []),
        )

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_kind(cls, kind, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_LirAbiBinding.from_kind(kind, cpu))

    @classmethod
    def sysv(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_LirAbiBinding.sysv(cpu))

    @classmethod
    def windows64(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_LirAbiBinding.windows64(cpu))

    @classmethod
    def cdecl(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_LirAbiBinding.cdecl(cpu))

    @classmethod
    def stdcall(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_LirAbiBinding.stdcall(cpu))

    @classmethod
    def fastcall(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_LirAbiBinding.fastcall(cpu))

    @classmethod
    def linux_syscall(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_LirAbiBinding.linux_syscall(cpu))

    @classmethod
    def windows_syscall(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_LirAbiBinding.windows_syscall(cpu))

    def __getattr__(self, name):
        return getattr(self._inner, name)


class _LirVariantWrapper:
    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(cls._binding.from_dict(data))

    def to_dict(self):
        return self._inner.to_dict()

    def json(self):
        return self._inner.json()

    def print(self):
        self._inner.print()

    def __str__(self):
        return self.json()

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


class Lir:
    """Wrapper around the Rust low-level instruction IR object."""

    def __init__(
        self,
        version,
        status,
        abi=None,
        encoding=None,
        temporaries=None,
        effects=None,
        terminator=None,
        diagnostics=None,
        metadata=None,
    ):
        abi = getattr(abi, "_inner", abi)
        encoding = _unwrap(encoding)
        temporaries = [_unwrap(item) for item in list(temporaries or [])]
        effects = [_unwrap(item) for item in list(effects or [])]
        terminator = _unwrap(terminator) if terminator is not None else None
        diagnostics = [_unwrap(item) for item in list(diagnostics or [])]
        self._inner = _LirBinding(
            version=version,
            status=status,
            abi=abi,
            encoding=encoding,
            temporaries=temporaries,
            effects=effects,
            terminator=terminator,
            diagnostics=diagnostics,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_LirBinding.from_dict(data))

    def abi(self):
        abi = self._inner.abi()
        if abi is None:
            return None
        return LirAbi._from_inner(abi)

    def set_abi(self, abi):
        abi = getattr(abi, "_inner", abi)
        self._inner.set_abi(abi)

    def metadata(self):
        return self._inner.metadata()

    def set_metadata(self, metadata):
        self._inner.set_metadata(dict(metadata or {}))

    def get_metadata_value(self, key):
        return self._inner.get_metadata_value(key)

    def set_metadata_value(self, key, value):
        self._inner.set_metadata_value(key, value)

    def remove_metadata_value(self, key):
        self._inner.remove_metadata_value(key)

    def optimize_constants(self):
        self._inner.optimize_constants()

    def optimize_identities(self):
        self._inner.optimize_identities()

    def optimize_casts(self):
        self._inner.optimize_casts()

    def optimize_noops(self):
        self._inner.optimize_noops()

    def optimize_branches(self):
        self._inner.optimize_branches()

    def optimize_intrinsics(self):
        self._inner.optimize_intrinsics()

    def optimize(self):
        self._inner.optimize()

    def text(self):
        return self._inner.text()

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


class LirExecutor:
    """Symbolically executes LIR modules and instructions."""

    def __init__(self):
        self._inner = _LirExecutorBinding()

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    def step(self, semantics, state):
        return [
            LirExecutorState._from_inner(item)
            for item in self._inner.step(_unwrap(semantics), _unwrap(state))
        ]

    def run(self, semantics, state, steps=None):
        return [
            LirExecutorState._from_inner(item)
            for item in self._inner.run(_unwrap(semantics), _unwrap(state), steps)
        ]

    def run_with_hooks(self, semantics, state, steps=None):
        return [
            LirExecutorState._from_inner(item)
            for item in self._inner.run_with_hooks(_unwrap(semantics), _unwrap(state), steps)
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

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_LirDataBinding.from_dict(data))

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirBlock:
    """Block-scoped container for low-level instructions."""

    def __init__(self, name=None, instructions=None):
        instructions = [getattr(item, "_inner", item) for item in list(instructions or [])]
        self._inner = _LirBlockBinding(name=name, instructions=instructions)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_LirBlockBinding.from_dict(data))

    def instructions(self):
        return [Lir._from_inner(item) for item in self._inner.instructions()]

    def set_instructions(self, instructions):
        instructions = [getattr(item, "_inner", item) for item in instructions]
        self._inner.set_instructions(instructions)

    def append_instruction(self, instruction):
        instruction = getattr(instruction, "_inner", instruction)
        self._inner.append_instruction(instruction)

    def optimize_constants(self):
        self._inner.optimize_constants()

    def optimize_identities(self):
        self._inner.optimize_identities()

    def optimize_casts(self):
        self._inner.optimize_casts()

    def optimize_noops(self):
        self._inner.optimize_noops()

    def optimize_branches(self):
        self._inner.optimize_branches()

    def optimize_intrinsics(self):
        self._inner.optimize_intrinsics()

    def optimize(self):
        self._inner.optimize()

    def text(self):
        return self._inner.text()

    def print(self):
        self._inner.print()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirFunction:
    """Function-scoped low-level IR."""

    def __init__(self, name=None, abi=None, blocks=None):
        abi = getattr(abi, "_inner", abi)
        blocks = [getattr(item, "_inner", item) for item in list(blocks or [])]
        self._inner = _LirFunctionBinding(name=name, abi=abi, blocks=blocks)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_LirFunctionBinding.from_dict(data))

    def abi(self):
        abi = self._inner.abi()
        if abi is None:
            return None
        return LirAbi._from_inner(abi)

    def set_abi(self, abi):
        abi = getattr(abi, "_inner", abi)
        self._inner.set_abi(abi)

    def blocks(self):
        return [LirBlock._from_inner(item) for item in self._inner.blocks()]

    def set_blocks(self, blocks):
        blocks = [getattr(item, "_inner", item) for item in blocks]
        self._inner.set_blocks(blocks)

    def append_block(self, block):
        block = getattr(block, "_inner", block)
        self._inner.append_block(block)

    def optimize_constants(self):
        self._inner.optimize_constants()

    def optimize_identities(self):
        self._inner.optimize_identities()

    def optimize_casts(self):
        self._inner.optimize_casts()

    def optimize_noops(self):
        self._inner.optimize_noops()

    def optimize_branches(self):
        self._inner.optimize_branches()

    def optimize_intrinsics(self):
        self._inner.optimize_intrinsics()

    def optimize(self):
        self._inner.optimize()

    def text(self):
        return self._inner.text()

    def print(self):
        self._inner.print()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class LirModule:
    """Module-scoped low-level IR."""

    def __init__(self, name=None, functions=None, data=None):
        functions = [getattr(item, "_inner", item) for item in list(functions or [])]
        data = [getattr(item, "_inner", item) for item in list(data or [])]
        self._inner = _LirModuleBinding(name=name, functions=functions, data=data)
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
        return cls._from_inner(_LirModuleBinding.from_dict(data))

    @classmethod
    def from_text(cls, text):
        return cls._from_mlir_inner(_LirModuleBinding.from_text(text))

    @classmethod
    def from_bytecode(cls, bytecode):
        return cls._from_mlir_inner(_LirModuleBinding.from_bytecode(bytecode))

    def functions(self):
        return [LirFunction._from_inner(item) for item in self._inner.functions()]

    def data(self):
        return [LirData._from_inner(item) for item in self._inner.data()]

    def set_functions(self, functions):
        functions = [getattr(item, "_inner", item) for item in functions]
        self._inner.set_functions(functions)

    def append_function(self, function):
        function = getattr(function, "_inner", function)
        self._inner.append_function(function)

    def set_data(self, data):
        data = [getattr(item, "_inner", item) for item in data]
        self._inner.set_data(data)

    def append_data(self, data):
        data = getattr(data, "_inner", data)
        self._inner.append_data(data)

    def optimize_constants(self):
        self._inner.optimize_constants()

    def optimize_identities(self):
        self._inner.optimize_identities()

    def optimize_casts(self):
        self._inner.optimize_casts()

    def optimize_noops(self):
        self._inner.optimize_noops()

    def optimize_branches(self):
        self._inner.optimize_branches()

    def optimize_intrinsics(self):
        self._inner.optimize_intrinsics()

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
