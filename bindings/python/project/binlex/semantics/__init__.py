"""Rust-backed instruction semantics bindings."""

from binlex_bindings.binlex.semantics import *
from binlex_bindings.binlex.semantics import SemanticAbi as _SemanticAbiBinding
from binlex_bindings.binlex.semantics import SemanticCpu as _SemanticCpuBinding
from binlex_bindings.binlex.semantics import Semantic as _SemanticBinding

from binlex.core.architecture import Architecture


def _cpu_kind_from_architecture(architecture):
    if isinstance(architecture, Architecture):
        value = architecture.value
    else:
        value = str(architecture)
    if value == "amd64":
        return SemanticCpuKind.Amd64
    if value == "i386":
        return SemanticCpuKind.I386
    if value == "arm64":
        return SemanticCpuKind.Arm64
    if value == "cil":
        return SemanticCpuKind.Cil
    raise ValueError(f"unsupported architecture for semantic cpu: {value}")


class SemanticCpu:
    """Declarative CPU model for semantics and symbolic execution."""

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
        self._inner = _SemanticCpuBinding(
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
        return cls._from_inner(_SemanticCpuBinding.from_kind(kind))

    @classmethod
    def i386(cls):
        return cls._from_inner(_SemanticCpuBinding.i386())

    @classmethod
    def amd64(cls):
        return cls._from_inner(_SemanticCpuBinding.amd64())

    @classmethod
    def arm64(cls):
        return cls._from_inner(_SemanticCpuBinding.arm64())

    @classmethod
    def cil(cls):
        return cls._from_inner(_SemanticCpuBinding.cil())

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


class SemanticAbi:
    """Declarative ABI model for semantics and lifting."""

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
        self._inner = _SemanticAbiBinding(
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
        return cls._from_inner(_SemanticAbiBinding.from_kind(kind, cpu))

    @classmethod
    def sysv(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_SemanticAbiBinding.sysv(cpu))

    @classmethod
    def windows64(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_SemanticAbiBinding.windows64(cpu))

    @classmethod
    def cdecl(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_SemanticAbiBinding.cdecl(cpu))

    @classmethod
    def stdcall(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_SemanticAbiBinding.stdcall(cpu))

    @classmethod
    def fastcall(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_SemanticAbiBinding.fastcall(cpu))

    @classmethod
    def linux_syscall(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_SemanticAbiBinding.linux_syscall(cpu))

    @classmethod
    def windows_syscall(cls, cpu):
        cpu = getattr(cpu, "_inner", cpu)
        return cls._from_inner(_SemanticAbiBinding.windows_syscall(cpu))

    def __getattr__(self, name):
        return getattr(self._inner, name)


class Semantic:
    """Wrapper around the Rust semantic IR object."""

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
        self._inner = _SemanticBinding(
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
        return cls._from_inner(_SemanticBinding.from_dict(data))

    def abi(self):
        abi = self._inner.abi()
        if abi is None:
            return None
        return SemanticAbi._from_inner(abi)

    def set_abi(self, abi):
        abi = getattr(abi, "_inner", abi)
        self._inner.set_abi(abi)

    def __getattr__(self, name):
        return getattr(self._inner, name)
