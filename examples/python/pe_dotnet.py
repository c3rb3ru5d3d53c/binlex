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


from binlex.formats import PE
from binlex.disassemblers.cil import Disassembler
from binlex.controlflow import Graph
from binlex import Config
import argparse

__version__ = '1.0.0'
__author__ = 'c3rb3ru5d3d53c'

parser = argparse.ArgumentParser(
    prog=f'pe_dotnet v{__version__}',
    description='Compare to Native PE Files',
    epilog=f'Author: {__author__}'
)
parser.add_argument(
    '--input',
    type=str,
    default=None,
    help='Input DotNet PE File Path',
    required=True
)

args = parser.parse_args()

# Get Default Configuration
config = Config()

# Use 16 Threads for Multi-Threaded Operations
config.general.threads = 16

# Open the PE File
pe = PE(args.input, config)

# To check if a DotNet PE use ps.is_dotnet()

# Get the Memory Mapped File
mapped_file = pe.image()

# Get the Memory Map
image = mapped_file.mmap()

# Create Disassembler on Mapped PE Image and PE Architecture
disassembler = Disassembler(pe.architecture(), image, pe.dotnet_metadata_token_virtual_addresses(), pe.dotnet_executable_virtual_address_ranges(), config)

# Create the Controlflow Graph
cfg = Graph(pe.architecture(), config)

# Disassemble the PE Image Entrypoints Recursively
disassembler.disassemble_controlflow(pe.dotnet_entrypoint_virtual_addresses(), cfg)

for function in cfg.functions():
    function.print()
