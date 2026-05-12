# MIT License
#
# Copyright (c) [2025] [c3rb3ru5d3d53c]
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""LLVM lifter wrappers backed by the Rust core implementation."""

import ctypes

from binlex_bindings.binlex.lifters.llvm import JittedFunction as _JittedFunctionBinding
from binlex_bindings.binlex.lifters.llvm import Lifter as _LifterBinding
from binlex_bindings.binlex.lifters.llvm import LiftedBlock as _LiftedBlockBinding
from binlex_bindings.binlex.lifters.llvm import LiftedFunction as _LiftedFunctionBinding


class Lifter:
    """Lift instructions, blocks, and functions into LLVM-style IR."""

    def __init__(self, cpu, config, triple=None, _inner=None):
        self._cpu = cpu
        self._config = config
        if _inner is None:
            cpu = getattr(cpu, "_inner", cpu)
            self._inner = _LifterBinding(cpu, config, triple)
        else:
            self._inner = _inner

    def lift_instruction(self, instruction):
        if self._inner.lift_instruction(instruction._inner):
            return self
        return None

    def lift_block(self, block, abi=None):
        if self._inner.lift_block(block._inner, abi):
            return self
        return None

    def lift_function(self, function, abi=None):
        if self._inner.lift_function(function._inner, abi):
            return self
        return None

    def lift_block_semantics(self, semantics, abi=None):
        semantics = getattr(semantics, "_inner", semantics)
        if not self._inner.lift_block_semantics(semantics, abi):
            return None
        return self

    def lift_function_semantics(self, semantics, abi=None, name=None):
        semantics = getattr(semantics, "_inner", semantics)
        if not self._inner.lift_function_semantics(semantics, abi, name):
            return None
        return self

    def create_function(self, name, abi=None):
        inner = self._inner.create_function(name, abi)
        return LiftedFunction(self, inner)

    def functions(self):
        return [LiftedFunction(self, inner) for inner in self._inner.functions()]

    def clear(self):
        if self._inner.clear():
            return self
        return None

    def ir(self):
        return self._inner.ir()

    def set_ir(self, ir):
        if self._inner.set_ir(ir):
            return self
        return None

    def set_bitcode(self, bitcode):
        if self._inner.set_bitcode(bitcode):
            return self
        return None

    def print(self):
        return self._inner.print()

    def bitcode(self):
        return bytes(self._inner.bitcode())

    def object(self):
        return bytes(self._inner.object())

    def optimize_mem2reg(self):
        if self._inner.optimize_mem2reg():
            return self
        return None

    def optimize_instcombine(self):
        if self._inner.optimize_instcombine():
            return self
        return None

    def optimize_cfg(self):
        if self._inner.optimize_cfg():
            return self
        return None

    def optimize_gvn(self):
        if self._inner.optimize_gvn():
            return self
        return None

    def optimize_sroa(self):
        if self._inner.optimize_sroa():
            return self
        return None

    def optimize_dce(self):
        if self._inner.optimize_dce():
            return self
        return None

    def verify(self):
        return self._inner.verify()

    def __str__(self):
        return self.ir()


__all__ = ["Lifter", "LiftedFunction", "LiftedBlock", "NativeFunction"]


class LiftedFunction:
    def __init__(self, lifter, inner):
        self._lifter = lifter
        self._inner = inner

    def name(self):
        return self._inner.name()

    def set_name(self, name):
        if self._inner.set_name(name):
            return self
        return None

    def blocks(self):
        return [LiftedBlock(self, inner) for inner in self._inner.blocks()]

    def lift_block(self, block, name=None):
        if self._inner.lift_block(block._inner, name):
            return self
        return None

    def lift_block_semantics(self, semantics, name=None):
        semantics = getattr(semantics, "_inner", semantics)
        if self._inner.lift_block_semantics(semantics, name):
            return self
        return None

    def lift_function_semantics(self, semantics):
        semantics = getattr(semantics, "_inner", semantics)
        if self._inner.lift_function_semantics(semantics):
            return self
        return None

    def optimize_mem2reg(self):
        if self._inner.optimize_mem2reg():
            return self
        return None

    def optimize_instcombine(self):
        if self._inner.optimize_instcombine():
            return self
        return None

    def optimize_cfg(self):
        if self._inner.optimize_cfg():
            return self
        return None

    def optimize_gvn(self):
        if self._inner.optimize_gvn():
            return self
        return None

    def optimize_sroa(self):
        if self._inner.optimize_sroa():
            return self
        return None

    def optimize_dce(self):
        if self._inner.optimize_dce():
            return self
        return None

    def ir(self):
        return self._inner.ir()

    def set_ir(self, ir):
        if self._inner.set_ir(ir):
            return self
        return None

    def set_bitcode(self, bitcode):
        if self._inner.set_bitcode(bitcode):
            return self
        return None

    def print(self):
        return self._inner.print()

    def bitcode(self):
        data = self._inner.bitcode()
        return None if data is None else bytes(data)

    def object(self):
        data = self._inner.object()
        return None if data is None else bytes(data)

    def jit(self, return_type=None, parameter_types=None, links=None):
        resolved_links = _resolve_jit_links(links or {})
        handle = self._inner.jit(resolved_links)
        if handle is None:
            return None
        return NativeFunction(
            handle,
            return_type=return_type,
            parameter_types=parameter_types,
        )


class LiftedBlock:
    def __init__(self, function, inner):
        self._function = function
        self._inner = inner

    def name(self):
        return self._inner.name()

    def ir(self):
        return self._inner.ir()

    def print(self):
        return self._inner.print()


class NativeFunction:
    def __init__(self, handle, return_type=None, parameter_types=None):
        if not isinstance(handle, _JittedFunctionBinding):
            raise TypeError("handle must be a binlex llvm jitted function")
        self._handle = handle
        self._return_type = ctypes.c_int if return_type is None else return_type
        self._parameter_types = list(parameter_types or [])
        self._functype = ctypes.CFUNCTYPE(self._return_type, *self._parameter_types)
        self._callable = self._functype(handle.address())

    def name(self):
        return self._handle.name()

    def address(self):
        return self._handle.address()

    def __call__(self, *args):
        return self._callable(*args)


def _resolve_jit_links(links):
    resolved = {}
    for name, value in links.items():
        resolved[str(name)] = _resolve_jit_link_target(str(name), value)
    return resolved


def _resolve_jit_link_target(name, value):
    if isinstance(value, NativeFunction):
        return int(value.address())
    if isinstance(value, _JittedFunctionBinding):
        return int(value.address())
    if isinstance(value, int):
        return int(value)

    target = value
    if _looks_like_ctypes_library(value):
        try:
            target = getattr(value, name)
        except AttributeError as exc:
            raise ValueError(f"jit link target {name!r} not found on module {value!r}") from exc

    try:
        pointer = ctypes.cast(target, ctypes.c_void_p).value
    except Exception as exc:
        raise TypeError(
            f"unsupported jit link target for {name!r}: expected ctypes module, ctypes function, raw address, or jitted function"
        ) from exc
    if pointer is None:
        raise ValueError(f"jit link target for {name!r} does not have an address")
    return int(pointer)


def _looks_like_ctypes_library(value):
    return hasattr(value, "_handle") and not hasattr(value, "address")
