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
"""Disassembler implementations exposed by the Python bindings."""

from enum import Enum

from binlex.controlflow import Block, Function, Graph, Instruction
from binlex.core import Architecture

from .capstone import Disassembler as _CapstoneDisassembler
from .cil import Disassembler as _CilDisassembler


class DisassemblerBackend(str, Enum):
    Default = "default"
    Capstone = "capstone"
    Native = "native"


class Disassembler:
    def __init__(
        self,
        graph: Graph,
        backend: DisassemblerBackend = DisassemblerBackend.Default,
    ) -> None:
        if not isinstance(graph, Graph):
            raise TypeError("disassembler graph must be a binlex.controlflow.Graph")
        self.graph = graph
        self.architecture = graph.architecture()
        self.backend = (
            backend
            if isinstance(backend, DisassemblerBackend)
            else DisassemblerBackend(backend)
        )

        resolved_backend = self.backend
        if resolved_backend == DisassemblerBackend.Default:
            resolved_backend = (
                DisassemblerBackend.Native
                if self.architecture == Architecture.CIL
                else DisassemblerBackend.Capstone
            )

        if self.architecture == Architecture.CIL:
            if resolved_backend != DisassemblerBackend.Native:
                raise ValueError("CIL only supports the Native backend")
            self._inner = _CilDisassembler(graph)
        else:
            if resolved_backend != DisassemblerBackend.Capstone:
                raise ValueError(
                    f"{self.architecture} only supports the Capstone backend"
                )
            self._inner = _CapstoneDisassembler(graph)

    def disassemble_instruction(self, address: int) -> Instruction:
        if self.architecture == Architecture.CIL:
            return self._inner.disassemble_instruction(
                address,
            )
        return self._inner.disassemble_instruction(address)

    def disassemble_function(self, address: int) -> Function:
        if self.architecture == Architecture.CIL:
            return self._inner.disassemble_function(
                address,
            )
        return self._inner.disassemble_function(address)

    def disassemble_block(self, address: int) -> Block:
        if self.architecture == Architecture.CIL:
            return self._inner.disassemble_block(
                address,
            )
        return self._inner.disassemble_block(address)

    def disassemble(self, addresses: set[int]) -> None:
        if self.architecture == Architecture.CIL:
            return self._inner.disassemble(
                addresses,
            )
        return self._inner.disassemble(addresses)

    def disassemble_sweep(self) -> set[int]:
        return self._inner.disassemble_sweep()

    def __getattr__(self, name):
        return getattr(self._inner, name)


__all__ = ["Disassembler", "DisassemblerBackend"]
