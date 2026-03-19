#!/usr/bin/env python

import sys
from binlex import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.formats import PE
from binlex.lifters.vex import Lifter
from binlex.imaging import Palette, PNG

# Create shared configuration
config = Config()

config.general.threads = 16

# Load PE and map image
pe = PE(sys.argv[1], config)

image = pe.image()

mmap = image.mmap()

# Disassemble control flow
disassembler = Disassembler(
    pe.architecture(),
    mmap,
    pe.executable_virtual_address_ranges(),
    config,
)

# Create Controlflow Graph
cfg = Graph(pe.architecture(), config)

# Disassemble the PE
disassembler.disassemble_controlflow(
    pe.entrypoint_virtual_addresses(),
    cfg,
)

function = cfg.functions()[0]
lifter = Lifter(pe.architecture(), function.bytes(), function.address(), config)
print(lifter.ir())

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
