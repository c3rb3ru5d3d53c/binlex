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

from binlex_bindings.binlex.lifters.llvm import Lifter as _LifterBinding

from .abi import Abi


class Lifter:
    """Lift instructions, blocks, and functions into LLVM-style IR."""

    def __init__(self, architecture, config, _inner=None):
        self._architecture = architecture
        self._config = config
        if _inner is None:
            architecture = architecture.to_binding() if hasattr(architecture, "to_binding") else architecture
            self._inner = _LifterBinding(architecture, config)
        else:
            self._inner = _inner

    def lift_instruction(self, instruction):
        if self._inner.lift_instruction(instruction._inner):
            return self
        return None

    def lift_block(self, block):
        if self._inner.lift_block(block._inner):
            return self
        return None

    def lift_function(self, function):
        if self._inner.lift_function(function._inner):
            return self
        return None

    def lift_semantics(self, semantics):
        inner = getattr(semantics, "_inner", semantics)
        if self._inner.lift_semantics(inner):
            return self
        return None

    def text(self):
        return self._inner.text()

    def print(self):
        return self._inner.print()

    def bitcode(self):
        return bytes(self._inner.bitcode())

    def object(self):
        return bytes(self._inner.object())

    def normalized(self):
        inner = self._inner.normalized()
        if inner is None:
            return None
        return self.__class__(self._architecture, self._config, _inner=inner)

    def optimizers(self):
        return Optimizers(self)

    def verify(self):
        return self._inner.verify()

    def __str__(self):
        return self.text()


class Optimizers:
    """Chain standard LLVM optimizer passes over a lifted artifact."""

    def __init__(self, lifter):
        self._lifter = lifter

    def optimizers(self):
        return self

    def mem2reg(self):
        if self._lifter is not None:
            self._lifter = self._apply("mem2reg")
        return self

    def instcombine(self):
        if self._lifter is not None:
            self._lifter = self._apply("instcombine")
        return self

    def cfg(self):
        if self._lifter is not None:
            self._lifter = self._apply("cfg")
        return self

    def gvn(self):
        if self._lifter is not None:
            self._lifter = self._apply("gvn")
        return self

    def sroa(self):
        if self._lifter is not None:
            self._lifter = self._apply("sroa")
        return self

    def dce(self):
        if self._lifter is not None:
            self._lifter = self._apply("dce")
        return self

    def _apply(self, name):
        inner = getattr(self._lifter._inner, name)()
        if inner is None:
            return None
        return self._lifter.__class__(self._lifter._architecture, self._lifter._config, _inner=inner)

    def text(self):
        if self._lifter is None:
            return None
        return self._lifter.text()

    def print(self):
        if self._lifter is None:
            return None
        return self._lifter.print()

    def bitcode(self):
        if self._lifter is None:
            return None
        return self._lifter.bitcode()

    def object(self):
        if self._lifter is None:
            return None
        return self._lifter.object()

    def normalized(self):
        if self._lifter is None:
            return None
        return self._lifter.normalized()

    def verify(self):
        if self._lifter is None:
            return None
        return self._lifter.verify()

    def __str__(self):
        text = self.text()
        return "" if text is None else text


__all__ = ["Abi", "Lifter", "Optimizers"]
