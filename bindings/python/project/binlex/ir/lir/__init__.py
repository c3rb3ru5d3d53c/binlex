"""Rust-backed LIR bindings."""

from binlex_bindings.binlex.ir.lir import *
from binlex_bindings.binlex.ir.lir import LirAbi as _LirAbiBinding
from binlex_bindings.binlex.ir.lir import LirCpu as _LirCpuBinding
from binlex_bindings.binlex.ir.lir import LirData as _LirDataBinding
from binlex_bindings.binlex.ir.lir import Lir as _LirBinding
from binlex_bindings.binlex.ir.lir import LirModule as _LirsBinding

from binlex.core.architecture import Architecture


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


class Lir:
    """Wrapper around the Rust low-level IR object."""

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
    ):
        abi = getattr(abi, "_inner", abi)
        self._inner = _LirBinding(
            version=version,
            status=status,
            abi=abi,
            encoding=encoding,
            temporaries=list(temporaries or []),
            effects=list(effects or []),
            terminator=terminator,
            diagnostics=list(diagnostics or []),
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

    def optimize_simplify(self):
        self._inner.optimize_simplify()

    def text(self):
        return self._inner.text()

    def __str__(self):
        return self.text()

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


class LirModule:
    """Lir instructions plus attached static data."""

    def __init__(self, semantics=None, data=None):
        semantics = [getattr(item, "_inner", item) for item in list(semantics or [])]
        data = [getattr(item, "_inner", item) for item in list(data or [])]
        self._inner = _LirsBinding(semantics=semantics, data=data)

    @classmethod
    def _from_inner(cls, inner):
        instance = cls.__new__(cls)
        instance._inner = inner
        return instance

    @classmethod
    def from_dict(cls, data):
        return cls._from_inner(_LirsBinding.from_dict(data))

    def semantics(self):
        return [Lir._from_inner(item) for item in self._inner.semantics()]

    def data(self):
        return [LirData._from_inner(item) for item in self._inner.data()]

    def set_semantics(self, semantics):
        semantics = [getattr(item, "_inner", item) for item in semantics]
        self._inner.set_semantics(semantics)

    def append_semantic(self, semantic):
        semantic = getattr(semantic, "_inner", semantic)
        self._inner.append_semantic(semantic)

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

    def optimize_simplify(self):
        self._inner.optimize_simplify()

    def text(self):
        return self._inner.text()

    def __str__(self):
        return self.text()

    def __getattr__(self, name):
        return getattr(self._inner, name)
