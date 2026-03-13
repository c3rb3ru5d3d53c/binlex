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

from binlex_bindings.binlex.controlflow import Block
from binlex_bindings.binlex.controlflow import BlockJsonDeserializer
from binlex_bindings.binlex.controlflow import Function
from binlex_bindings.binlex.controlflow import FunctionJsonDeserializer
from binlex_bindings.binlex.controlflow import Graph as _GraphBinding
from binlex_bindings.binlex.controlflow import GraphQueue
from binlex_bindings.binlex.controlflow import Instruction

from binlex.architecture import _coerce_architecture


class Graph:
    def __init__(self, architecture, config):
        self._inner = _GraphBinding(_coerce_architecture(architecture), config)

    def instructions(self):
        return self._inner.instructions()

    def blocks(self):
        return self._inner.blocks()

    def functions(self):
        return self._inner.functions()

    @property
    def queue_instructions(self):
        return self._inner.queue_instructions

    @property
    def queue_blocks(self):
        return self._inner.queue_blocks

    @property
    def queue_functions(self):
        return self._inner.queue_functions

    def set_block(self, address):
        return self._inner.set_block(address)

    def set_function(self, address):
        return self._inner.set_function(address)

    def extend_instruction_edges(self, address, addresses):
        return self._inner.extend_instruction_edges(address, addresses)

    def get_instruction(self, address):
        return self._inner.get_instruction(address)

    def __getattr__(self, name):
        return getattr(self._inner, name)

__all__ = [
    "Block",
    "BlockJsonDeserializer",
    "Function",
    "FunctionJsonDeserializer",
    "Graph",
    "GraphQueue",
    "Instruction",
]
