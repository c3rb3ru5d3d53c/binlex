#!/usr/bin/env python

import sys

from binlex import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import PE


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <pe-file> [worker-dir]", file=sys.stderr)
        return 1

    config = Config()
    config.general.threads = 16
    config.processors.enabled = True
    config.processors.processes = 2
    config.processors.compression = True
    config.processors.vex.enabled = True
    config.processors.vex.functions.enabled = True

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

    print(functions[0].to_dict())


    return 0


if __name__ == "__main__":
    raise SystemExit(main())
