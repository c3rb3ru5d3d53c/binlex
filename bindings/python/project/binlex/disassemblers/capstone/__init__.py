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

"""Capstone-backed disassembly helpers for native instruction sets."""

from binlex_bindings.binlex.disassemblers.capstone import Disassembler as _DisassemblerBinding

from binlex import Architecture, Configuration
from binlex.controlflow import Block, Function, Graph, Instruction
from binlex.core.architecture import _coerce_architecture
from binlex.formats import Image


class Disassembler:
    """Disassemble native executable regions into a control-flow graph."""

    def __init__(
        self,
        machine: Architecture,
        image: Image | bytes,
        executable_address_ranges: dict[int, int],
        configuration: Configuration,
    ) -> None:
        """Create a disassembler for the given architecture and image source."""
        if isinstance(image, Image):
            image = image._inner
        self._inner = _DisassemblerBinding(
            _coerce_architecture(machine),
            image,
            executable_address_ranges,
            configuration,
        )

    def disassemble_instruction(self, address: int, graph: Graph) -> Instruction:
        """Disassemble a single instruction into the provided graph."""
        return Instruction._from_binding(
            self._inner.disassemble_instruction(address, graph._inner),
            graph._config,
        )

    def disassemble_function(self, address: int, graph: Graph) -> Function:
        """Disassemble the function that starts at `address` into the graph."""
        return Function._from_binding(
            self._inner.disassemble_function(address, graph._inner),
            graph._config,
        )

    def disassemble_block(self, address: int, graph: Graph) -> Block:
        """Disassemble the basic block that starts at `address`."""
        return Block._from_binding(
            self._inner.disassemble_block(address, graph._inner),
            graph._config,
        )

    def disassemble(self, addresses: set[int], graph: Graph) -> None:
        """Disassemble a set of entrypoint addresses into the graph."""
        return self._inner.disassemble(addresses, graph._inner)

    def disassemble_sweep(self) -> set[int]:
        """Return candidate addresses discovered during a linear sweep."""
        return self._inner.disassemble_sweep()

    def __getattr__(self, name):
        return getattr(self._inner, name)

__all__ = ["Disassembler"]
