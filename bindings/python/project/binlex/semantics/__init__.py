"""Rust-backed instruction semantics bindings."""

from binlex_bindings.binlex.semantics import *
from binlex_bindings.binlex.semantics import SemanticCpu as _SemanticCpuBinding

from binlex.core.architecture import _coerce_architecture


class SemanticCpu:
    """Declarative CPU model for semantics and symbolic execution."""

    def __init__(
        self,
        source=None,
        *,
        name=None,
        address_bits=None,
        endian=None,
        registers=None,
        aliases=None,
        program_counter=None,
        memory=None,
    ):
        if source is not None:
            if any(
                value is not None
                for value in (
                    name,
                    address_bits,
                    endian,
                    registers,
                    aliases,
                    program_counter,
                    memory,
                )
            ):
                raise TypeError(
                    "SemanticCpu accepts either a built-in Architecture or a custom CPU definition, not both"
                )
            self._inner = _SemanticCpuBinding(_coerce_architecture(source))
            return

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

    def __getattr__(self, name):
        return getattr(self._inner, name)
