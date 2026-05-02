"""Lifter interfaces for converting controlflow into intermediate representations."""

from __future__ import annotations

from enum import Enum
from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from binlex import Architecture, Configuration
    from binlex.controlflow import Block, Function, Instruction
    from binlex.semantics import InstructionSemantics

_LAZY_SUBMODULES = {"llvm", "vex"}


class UnsupportedCapabilityError(RuntimeError):
    """Raised when a requested lifter capability is unavailable for a backend."""


class LifterBackend(str, Enum):
    DEFAULT = "default"
    LLVM = "llvm"
    VEX = "vex"


def _resolve_backend(backend: LifterBackend | str | None) -> LifterBackend:
    if isinstance(backend, LifterBackend):
        return backend
    if backend is None:
        return LifterBackend.DEFAULT
    if isinstance(backend, str):
        return LifterBackend(backend.lower())
    raise TypeError(f"unsupported lifter backend: {backend!r}")


class Lifter:
    """Unified lifter facade across supported backend implementations."""

    def __init__(
        self,
        architecture: Architecture,
        configuration: Configuration,
        backend: LifterBackend = LifterBackend.DEFAULT,
        _inner: Any = None,
    ) -> None:
        self._architecture = architecture
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

            self._inner = _LlvmLifter(architecture, configuration)
        elif self._resolved_backend == LifterBackend.VEX:
            from .vex import Lifter as _VexLifter

            self._inner = _VexLifter(configuration)
        else:
            raise ValueError(f"unsupported lifter backend: {self._resolved_backend!r}")

    @property
    def backend(self) -> LifterBackend:
        return self._resolved_backend

    @property
    def architecture(self) -> Architecture:
        return self._architecture

    @property
    def configuration(self) -> Configuration:
        return self._configuration

    def lift_instruction(self, instruction: Instruction) -> Lifter | None:
        if self._inner.lift_instruction(instruction):
            return self
        return None

    def lift_block(self, block: Block) -> Lifter | None:
        if self._inner.lift_block(block):
            return self
        return None

    def lift_function(self, function: Function) -> Lifter | None:
        if self._inner.lift_function(function):
            return self
        return None

    def lift_semantics(self, semantics: InstructionSemantics) -> Lifter | None:
        self._require_backend(LifterBackend.LLVM, "lift_semantics")
        if self._inner.lift_semantics(semantics):
            return self
        return None

    def text(self) -> str:
        return self._inner.text()

    def print(self) -> None:
        return self._inner.print()

    def bitcode(self) -> bytes:
        self._require_backend(LifterBackend.LLVM, "bitcode")
        return self._inner.bitcode()

    def embedding(self) -> list[float] | None:
        self._require_backend(LifterBackend.LLVM, "embedding")
        return self._inner.embedding()

    def object(self) -> bytes:
        self._require_backend(LifterBackend.LLVM, "object")
        return self._inner.object()

    def verify(self) -> Any:
        self._require_backend(LifterBackend.LLVM, "verify")
        return self._inner.verify()

    def optimizers(self) -> Optimizers:
        self._require_backend(LifterBackend.LLVM, "optimizers")
        return Optimizers(self)

    def mem2reg(self) -> Lifter:
        return self._apply_llvm_pass("mem2reg")

    def instcombine(self) -> Lifter:
        return self._apply_llvm_pass("instcombine")

    def cfg(self) -> Lifter:
        return self._apply_llvm_pass("cfg")

    def gvn(self) -> Lifter:
        return self._apply_llvm_pass("gvn")

    def sroa(self) -> Lifter:
        return self._apply_llvm_pass("sroa")

    def dce(self) -> Lifter:
        return self._apply_llvm_pass("dce")

    def __str__(self):
        return self.text()

    def _apply_llvm_pass(self, name: str) -> Lifter:
        self._require_backend(LifterBackend.LLVM, name)
        inner = getattr(self._inner._inner, name)()
        if inner is None:
            raise RuntimeError(f"llvm pass {name} failed")
        from .llvm import Lifter as _LlvmLifter

        return self.__class__(
            self._architecture,
            self._configuration,
            backend=LifterBackend.LLVM,
            _inner=_LlvmLifter(self._architecture, self._configuration, _inner=inner),
        )

    def _require_backend(self, backend: LifterBackend, capability: str) -> None:
        if self._resolved_backend != backend:
            raise UnsupportedCapabilityError(
                f"lifter backend {self._resolved_backend.value} does not support capability {capability}"
            )


class Optimizers:
    """Chain optimizer passes over a unified lifter artifact."""

    def __init__(self, lifter: Lifter) -> None:
        self._lifter = lifter

    def optimizers(self) -> Optimizers:
        return self

    def mem2reg(self) -> Optimizers:
        self._lifter = self._lifter.mem2reg()
        return self

    def instcombine(self) -> Optimizers:
        self._lifter = self._lifter.instcombine()
        return self

    def cfg(self) -> Optimizers:
        self._lifter = self._lifter.cfg()
        return self

    def gvn(self) -> Optimizers:
        self._lifter = self._lifter.gvn()
        return self

    def sroa(self) -> Optimizers:
        self._lifter = self._lifter.sroa()
        return self

    def dce(self) -> Optimizers:
        self._lifter = self._lifter.dce()
        return self

    def text(self) -> str:
        return self._lifter.text()

    def print(self) -> None:
        return self._lifter.print()

    def bitcode(self) -> bytes:
        return self._lifter.bitcode()

    def object(self) -> bytes:
        return self._lifter.object()

    def verify(self) -> Any:
        return self._lifter.verify()

    def __str__(self):
        return self.text()


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
    "Optimizers",
    "UnsupportedCapabilityError",
    "llvm",
    "vex",
]
