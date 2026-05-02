#!/usr/bin/env python3

import binlex
from binlex.assemblers import Assembler


architecture = binlex.Architecture.AMD64
config = binlex.Configuration()
assembler = Assembler(architecture, config)

data = assembler.assemble(0x400000, "xor eax, eax; ret")

print(data.hex())
