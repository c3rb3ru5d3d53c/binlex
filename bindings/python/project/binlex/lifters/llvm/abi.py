"""Typed LLVM ABI selectors."""

from binlex_bindings.binlex.lifters.llvm import abi as _abi

Abi = _abi.Abi

__all__ = ["Abi"]
