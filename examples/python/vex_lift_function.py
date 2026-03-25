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

import argparse

from binlex import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import PE
from binlex.lifters.vex import Lifter


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vex_lift_function",
        description="Lift the first discovered PE function to VEX IR",
    )
    parser.add_argument("--input", required=True, help="Input PE path")
    parser.add_argument(
        "--threads", type=int, default=16, help="Thread count for disassembly"
    )
    args = parser.parse_args()

    config = Config()
    config.general.threads = args.threads

    pe = PE(args.input, config)
    image = pe.image()

    disassembler = Disassembler(
        pe.architecture(),
        image,
        pe.executable_virtual_address_ranges(),
        config,
    )

    cfg = Graph(pe.architecture(), config)
    disassembler.disassemble(pe.entrypoint_virtual_addresses(), cfg)

    functions = cfg.functions()
    if not functions:
        print("no functions discovered")
        return 0

    function = functions[0]
    lifter = Lifter(pe.architecture(), function.bytes(), function.address(), config)
    print(lifter.ir())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# # Get First Function
# function_lhs = cfg.functions()[0]
# function_rhs = cfg.functions()[4]
#
# png_lhs = PNG(function_lhs.bytes(), Palette.REDBLACK, config)
# print('lhs')
# png_lhs.print()
# png_rhs = PNG(function_rhs.bytes(), Palette.REDBLACK, config)
# print('rhs')
# png_rhs.print()
#
# result = png_lhs.phash().compare(png_rhs.phash())
# print(result)
#
#
