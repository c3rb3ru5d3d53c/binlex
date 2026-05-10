#!/usr/bin/env python3

from binlex import Architecture
from binlex import Configuration
from binlex.assemblers import Assembler

configuration = Configuration()
assembler = Assembler(Architecture.AMD64, configuration)

data = assembler.assemble(0x400000, "xor eax, eax; ret")

print(data.hex())
