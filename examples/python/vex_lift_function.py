#!/usr/bin/env python

import sys
from binlex import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import PE
from binlex.lifters.vex import Lifter
from binlex.imaging import SVG, Palette
from binlex import Architecture

# Create shared configuration
config = Config()

# Load PE and map image
pe = PE(sys.argv[1], config)
mapped_file = pe.image()
image = mapped_file.mmap()

# Disassemble control flow
disassembler = Disassembler(
    Architecture.AMD64,
    image,
    pe.executable_virtual_address_ranges(),
    config,
)

# Create Controlflow Graph
cfg = Graph(Architecture.AMD64, config)

# Disassemble the PE
disassembler.disassemble_controlflow(
    pe.entrypoint_virtual_addresses(),
    cfg,
)

# Get First Function
function = cfg.functions()[0]

# Lift function bytes to VEX IR
lifter = Lifter(
    Architecture.AMD64,
    function.bytes(),
    function.address(),
    config,
)

print(lifter.ir())

svg = SVG(function.bytes(), Palette.GRAYSCALE)
svg.write('test.svg')

