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

from binlex.core.architecture import _coerce_architecture
from binlex.formats import Image


class Disassembler:
    """Disassemble native executable regions into a control-flow graph."""

    def __init__(self, machine, image, executable_address_ranges, config):
        """Create a disassembler for the given architecture and image source."""
        if isinstance(image, Image):
            image = image._inner
        self._inner = _DisassemblerBinding(
            _coerce_architecture(machine),
            image,
            executable_address_ranges,
            config,
        )

    def disassemble_instruction(self, address, cfg):
        """Disassemble a single instruction into the provided graph."""
        return self._inner.disassemble_instruction(address, cfg._inner)

    def disassemble_function(self, address, cfg):
        """Disassemble the function that starts at `address` into the graph."""
        return self._inner.disassemble_function(address, cfg._inner)

    def disassemble_block(self, address, cfg):
        """Disassemble the basic block that starts at `address`."""
        return self._inner.disassemble_block(address, cfg._inner)

    def disassemble(self, addresses, cfg):
        """Disassemble a set of entrypoint addresses into the graph."""
        return self._inner.disassemble(addresses, cfg._inner)

    def disassemble_sweep(self):
        """Return candidate addresses discovered during a linear sweep."""
        return self._inner.disassemble_sweep()

    def __getattr__(self, name):
        return getattr(self._inner, name)

__all__ = ["Disassembler"]
