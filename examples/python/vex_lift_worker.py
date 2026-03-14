#!/usr/bin/env python

import sys

from binlex import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import PE
from binlex.lifters.vex import Lifter
from binlex.imaging import Palette, Terminal


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <pe-file> [worker-dir]", file=sys.stderr)
        return 1

    config = Config()
    config.general.threads = 16

    config.processors.enabled = True
    config.processors.processes = 2
    config.processors.compression = True
    config.processors.path = '/home/c3rb3ru5/Tools/binlex/target/release/'
    config.processors.restart_on_crash = True

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

    function = cfg.functions()[0]

    lifter = Lifter(
        pe.architecture(),
        function.bytes(),
        function.address(),
        config,
    )

    print(lifter.ir())

    terminal = Terminal(function.bytes(), Palette.HEATMAP)
    terminal.print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
