#!/usr/bin/env python
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

import sys
from binlex.formats import MACHO
from binlex.disassemblers.capstone import Disassembler
from binlex.controlflow import Graph
from binlex import Configuration
from pathlib import Path

config = Configuration()

macho = MACHO(Path(sys.argv[1]).read_bytes(), config)

for slice in macho.slices():

  architecture = slice.architecture()

  image = slice.image()

  disassembler = Disassembler(
    slice.architecture(),
    slice.image(),
    slice.executable_virtual_address_ranges(),
    config
  )

  graph = Graph(architecture, config)

  disassembler.disassemble(slice.entrypoint_virtual_addresses(), graph)

  for function in graph.functions():
    function.print()
