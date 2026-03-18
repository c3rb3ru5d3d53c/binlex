#!/usr/bin/env python

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
    mmap = image.mmap()

    disassembler = Disassembler(
        pe.architecture(),
        mmap,
        pe.executable_virtual_address_ranges(),
        config,
    )

    cfg = Graph(pe.architecture(), config)
    disassembler.disassemble_controlflow(
        pe.entrypoint_virtual_addresses(),
        cfg,
    )

    functions = cfg.functions()

    function = functions[0]

    lifter = Lifter(pe.architecture(), function.bytes(), function.address(), config)

    print(lifter.ir())


    return 0


if __name__ == "__main__":
    raise SystemExit(main())
