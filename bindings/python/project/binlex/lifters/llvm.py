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

from binlex import Config
from binlex_bindings.binlex.lifters.llvm import Lifter as _LifterBinding


class Lifter:
    """Lift instructions, blocks, and functions into LLVM-style IR."""

    def __init__(self, config, _inner=None):
        self._config = config
        self._inner = _LifterBinding(config) if _inner is None else _inner

    def lift_instruction(self, instruction):
        self._inner.lift_instruction(instruction._inner)
        return self

    def lift_block(self, block):
        self._inner.lift_block(block._inner)
        return self

    def lift_function(self, function):
        self._inner.lift_function(function._inner)
        return self

    def text(self):
        return self._inner.text()

    def bitcode(self):
        return bytes(self._inner.bitcode())

    def normalized(self):
        return self.__class__(self._config, _inner=self._inner.normalized())

    def optimizers(self):
        return Optimizers(self)

    def mem2reg(self):
        return self.__class__(self._config, _inner=self._inner.mem2reg())

    def instcombine(self):
        return self.__class__(self._config, _inner=self._inner.instcombine())

    def cfg(self):
        return self.__class__(self._config, _inner=self._inner.cfg())

    def gvn(self):
        return self.__class__(self._config, _inner=self._inner.gvn())

    def sroa(self):
        return self.__class__(self._config, _inner=self._inner.sroa())

    def dce(self):
        return self.__class__(self._config, _inner=self._inner.dce())

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
        self._lifter = self._lifter.mem2reg()
        return self

    def instcombine(self):
        self._lifter = self._lifter.instcombine()
        return self

    def cfg(self):
        self._lifter = self._lifter.cfg()
        return self

    def gvn(self):
        self._lifter = self._lifter.gvn()
        return self

    def sroa(self):
        self._lifter = self._lifter.sroa()
        return self

    def dce(self):
        self._lifter = self._lifter.dce()
        return self

    def text(self):
        return self._lifter.text()

    def bitcode(self):
        return self._lifter.bitcode()

    def normalized(self):
        return self._lifter.normalized()

    def verify(self):
        return self._lifter.verify()

    def __str__(self):
        return self.text()


__all__ = ["Lifter", "Optimizers"]
