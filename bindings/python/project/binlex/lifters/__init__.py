"""Lifter interfaces for converting controlflow into intermediate representations."""

from __future__ import annotations

from enum import Enum
from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from binlex import Configuration
    from binlex.controlflow import Block, Function, Instruction
    from binlex.semantics import SemanticAbi, SemanticCpu, Semantics
    from .llvm import LiftedFunction

_LAZY_SUBMODULES = {"llvm", "vex"}


class UnsupportedCapabilityError(RuntimeError):
    """Raised when a requested lifter capability is unavailable for a backend."""


class LifterBackend(str, Enum):
    DEFAULT = "default"
    LLVM = "llvm"
    VEX = "vex"


def _resolve_backend(backend: LifterBackend) -> LifterBackend:
    if not isinstance(backend, LifterBackend):
        raise TypeError("backend must be a LifterBackend")
    return backend


class Lifter:
    """Unified lifter facade across supported backend implementations."""

    def __init__(
        self,
        cpu: SemanticCpu,
        configuration: Configuration,
        backend: LifterBackend = LifterBackend.DEFAULT,
        triple: str | None = None,
        _inner: Any = None,
    ) -> None:
        self._cpu = cpu
        self._configuration = configuration
        self._backend = _resolve_backend(backend)
        self._resolved_backend = (
            LifterBackend.LLVM if self._backend == LifterBackend.DEFAULT else self._backend
        )
        if _inner is not None:
            self._inner = _inner
            return

        if self._resolved_backend == LifterBackend.LLVM:
            from .llvm import Lifter as _LlvmLifter

            self._inner = _LlvmLifter(cpu, configuration, triple=triple)
        elif self._resolved_backend == LifterBackend.VEX:
            from .vex import Lifter as _VexLifter

            self._inner = _VexLifter(configuration, triple=triple)
        else:
            raise ValueError(f"unsupported lifter backend: {self._resolved_backend!r}")

    @property
    def backend(self) -> LifterBackend:
        return self._resolved_backend

    @property
    def cpu(self) -> SemanticCpu:
        return self._cpu

    @property
    def configuration(self) -> Configuration:
        return self._configuration

    def lift_instruction(self, instruction: Instruction) -> Lifter | None:
        if self._inner.lift_instruction(instruction):
            return self
        return None

    def lift_block(self, block: Block, abi: SemanticAbi | None = None) -> Lifter | None:
        if self._inner.lift_block(block, abi):
            return self
        return None

    def lift_function(self, function: Function, abi: SemanticAbi | None = None) -> Lifter | None:
        if self._inner.lift_function(function, abi):
            return self
        return None

    def lift_block_semantics(
        self,
        semantics: Semantics,
        abi: SemanticAbi | None = None,
    ) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "lift_block_semantics")
        return self._inner.lift_block_semantics(semantics, abi)

    def lift_function_semantics(
        self,
        semantics: Semantics,
        abi: SemanticAbi | None = None,
        name: str | None = None,
    ) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "lift_function_semantics")
        return self._inner.lift_function_semantics(semantics, abi, name)

    def create_function(
        self,
        name: str,
        abi: SemanticAbi | None = None,
    ) -> LiftedFunction:
        self._require_backend(LifterBackend.LLVM, "create_function")
        return self._inner.create_function(name, abi)

    def functions(self) -> list[LiftedFunction]:
        self._require_backend(LifterBackend.LLVM, "functions")
        return self._inner.functions()

    def clear(self) -> Lifter | None:
        if self._inner.clear():
            return self
        return None

    def ir(self) -> str:
        return self._inner.ir()

    def set_ir(self, ir: str) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "set_ir")
        if self._inner.set_ir(ir) is not None:
            return self
        return None

    def set_bitcode(self, bitcode: bytes) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "set_bitcode")
        if self._inner.set_bitcode(bitcode) is not None:
            return self
        return None

    def print(self) -> None:
        return self._inner.print()

    def bitcode(self) -> bytes:
        self._require_backend(LifterBackend.LLVM, "bitcode")
        return self._inner.bitcode()

    def object(self) -> bytes:
        self._require_backend(LifterBackend.LLVM, "object")
        return self._inner.object()

    def verify(self) -> Any:
        self._require_backend(LifterBackend.LLVM, "verify")
        return self._inner.verify()

    def optimize_mem2reg(self) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "optimize_mem2reg")
        if self._inner.optimize_mem2reg() is not None:
            return self
        return None

    def optimize_instcombine(self) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "optimize_instcombine")
        if self._inner.optimize_instcombine() is not None:
            return self
        return None

    def optimize_cfg(self) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "optimize_cfg")
        if self._inner.optimize_cfg() is not None:
            return self
        return None

    def optimize_gvn(self) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "optimize_gvn")
        if self._inner.optimize_gvn() is not None:
            return self
        return None

    def optimize_sroa(self) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "optimize_sroa")
        if self._inner.optimize_sroa() is not None:
            return self
        return None

    def optimize_dce(self) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "optimize_dce")
        if self._inner.optimize_dce() is not None:
            return self
        return None

    def __str__(self):
        return self.ir()

    def _require_backend(self, backend: LifterBackend, capability: str) -> None:
        if self._resolved_backend != backend:
            raise UnsupportedCapabilityError(
                f"lifter backend {self._resolved_backend.value} does not support capability {capability}"
            )


def __getattr__(name):
    """Load optional backend-specific lifter submodules on demand."""
    if name in _LAZY_SUBMODULES:
        module = import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "Lifter",
    "LifterBackend",
    "UnsupportedCapabilityError",
    "llvm",
    "vex",
]
