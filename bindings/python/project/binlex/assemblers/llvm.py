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

"""LLVM-backed assembly helpers for native instruction sets."""

from binlex import Configuration
from binlex_bindings.binlex.assemblers._llvm_assembler import (
    Assembler as _AssemblerBinding,
)

from binlex.core.architecture import _coerce_architecture


class Assembler:
    def __init__(self, architecture, config):
        if not isinstance(config, Configuration):
            raise TypeError("config must be a binlex.Configuration")
        self._inner = _AssemblerBinding(_coerce_architecture(architecture), config)

    def assemble(self, address, text):
        return self._inner.assemble(address, text)

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = ["Assembler"]
