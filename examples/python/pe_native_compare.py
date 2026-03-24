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

import json
from binlex.formats import PE
from binlex.disassemblers.capstone import Disassembler
from binlex.controlflow import Graph
from binlex.controlflow import Function
from binlex.controlflow import FunctionJsonDeserializer
from binlex import Config
import argparse

__version__ = '1.0.0'
__author__ = 'c3rb3ru5d3d53c'

parser = argparse.ArgumentParser(
    prog=f'pe_native_compare v{__version__}',
    description='Compare to Native PE Files',
    epilog=f'Author: {__author__}'
)
parser.add_argument(
    '--lhs',
    type=str,
    default=None,
    help='Input LHS PE File path',
    required=True
)
parser.add_argument(
    '--rhs',
    type=str,
    default=None,
    help='Input RHS PE File path',
    required=True
)

args = parser.parse_args()

# Get Default Configuration
config = Config()

# Use 16 Threads for Multi-Threaded Operations
config.general.threads = 16

# Open the LHS PE File
lhs_pe = PE(args.lhs, config)

# To check if a DotNet PE use ps.is_dotnet()

# Get the Image
lhs_image = lhs_pe.image()

# Create Disassembler on Mapped PE Image and PE Architecture
lhs_disassembler = Disassembler(lhs_pe.architecture(), lhs_image, lhs_pe.executable_virtual_address_ranges(), config)

# Create the Controlflow Graph
lhs_cfg = Graph(lhs_pe.architecture(), config)

# Disassemble the PE Image Entrypoints Recursively
lhs_disassembler.disassemble_controlflow(lhs_pe.entrypoint_virtual_addresses(), lhs_cfg)

# Open the RHS PE File
rhs_pe = PE(args.rhs, config)

# Get the Image
rhs_image = rhs_pe.image()

# Create Disassembler on Mapped PE Image and PE Architecture
rhs_disassembler = Disassembler(rhs_pe.architecture(), rhs_image, rhs_pe.executable_virtual_address_ranges(), config)

# Create the Controlflow Graph
rhs_cfg = Graph(rhs_pe.architecture(), config)

# Disassemble the PE Image Entrypoints Recursively
rhs_disassembler.disassemble_controlflow(rhs_pe.entrypoint_virtual_addresses(), rhs_cfg)

# lhs_blocks = lhs_cfg.blocks()
# rhs_blocks = rhs_cfg.blocks()
# lhs_block = lhs_blocks[0]


# for k, v in results.items():
#     v = json.loads(v.json())
#     if v['score']['minhash'] == None: continue
#     if v['score']['minhash'] <= 0.5: continue
#     print(json.dumps(v))

lhs_functions = lhs_cfg.functions()

rhs_functions = rhs_cfg.functions()

print(f'rhs_functions: {len(rhs_functions)}')

for lhs_function in lhs_functions:
    print(f'lhs_function: {lhs_function.address()}')
    print('function comparison API removed; compare emitted hashes in consumer code instead')

# lhs_filtered = []
# rhs_filtered = []

# # Filter by Size and Hashed Ratio
# for lhs in lhs_cfg.functions():
#     if lhs.size() < 128: continue
#     lhs_filtered.append(lhs)

# for rhs in rhs_cfg.functions():
#     if rhs.size() < 128: continue
#     rhs_filtered.append(rhs)

# # Hunt Similar Functions with Size Tolerance
# for lhs in lhs_filtered:
#   for rhs in rhs_filtered:
#     if abs(lhs.size() - rhs.size()) > 32: continue
#     if similarity is None: continue
#     if similarity.minhash() is None: continue
#     if similarity.minhash() < 0.25: continue
#     print(f'lhs[{hex(lhs.address)}] vs. rhs[{hex(rhs.address)}] -> similarity: {similarity.minhash()}')
