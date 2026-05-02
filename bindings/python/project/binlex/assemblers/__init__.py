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

"""Assembler implementations exposed by the Python bindings."""

from enum import Enum

from binlex import Configuration
from binlex.core import Architecture
from binlex.core.architecture import _coerce_architecture

from .llvm import Assembler as _LLVMAssembler


class AssemblerBackend(str, Enum):
    Default = "default"
    LLVM = "llvm"


class Assembler:
    def __init__(self, architecture, config, backend=AssemblerBackend.Default):
        binding_architecture = _coerce_architecture(architecture)
        self.architecture = Architecture.from_binding(binding_architecture)
        if not isinstance(config, Configuration):
            raise TypeError("config must be a binlex.Configuration")
        self.config = config
        self.backend = (
            backend
            if isinstance(backend, AssemblerBackend)
            else AssemblerBackend(backend)
        )

        resolved_backend = self.backend
        if resolved_backend == AssemblerBackend.Default:
            resolved_backend = AssemblerBackend.LLVM

        if resolved_backend != AssemblerBackend.LLVM:
            raise ValueError(
                f"{self.architecture} only supports the LLVM assembler backend"
            )

        self._inner = _LLVMAssembler(binding_architecture, self.config)

    def assemble(self, address, text):
        return self._inner.assemble(address, text)

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = ["Assembler", "AssemblerBackend"]
