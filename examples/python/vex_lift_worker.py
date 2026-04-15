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

from binlex import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import PE
from binlex.lifters.vex import Lifter


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <pe-file> [worker-dir]", file=sys.stderr)
        return 1

    config = Config()
    
    config.general.threads = 16

    if len(sys.argv) >= 3:
        config.processors.path = sys.argv[2]

    pe = PE(sys.argv[1], config)
    image = pe.image()

    disassembler = Disassembler(
        pe.architecture(),
        image,
        pe.executable_virtual_address_ranges(),
        config,
    )

    cfg = Graph(pe.architecture(), config)
    disassembler.disassemble(
        pe.entrypoint_virtual_addresses(),
        cfg,
    )

    functions = cfg.functions()

    function = functions[0]

    lifter = Lifter(config)
    lifter.lift_function(function)

    print(lifter.text())


    return 0


if __name__ == "__main__":
    raise SystemExit(main())
