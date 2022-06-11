#!/usr/bin/env python

import sys
import json
import pybinlex

raw = pybinlex.Raw()
raw.set_architecture(
    pybinlex.BINARY_ARCH.BINARY_ARCH_X86,
    pybinlex.BINARY_MODE.BINARY_MODE_32)
result = raw.read_file('../tests/raw/raw.x86')
if result is False: sys.exit(1)
disassembler = pybinlex.Disassembler(raw)
disassembler.disassemble()
traits = disassembler.get_traits()
print(json.dumps(traits, indent=4))

pe = pybinlex.PE()
result = pe.read_file('../tests/pe/pe.x86')
if result is False: sys.exit(1)
pe_sections = pe.get_sections()
disassembler = pybinlex.Disassembler(pe)
disassembler.disassemble()
traits = disassembler.get_traits()
print(json.dumps(traits, indent=4))

elf = pybinlex.ELF()
result = elf.read_file('../tests/elf/elf.x86')
if result is False: sys.exit(1)
disassembler = pybinlex.Disassembler(elf)
disassembler.disassemble()
traits = disassembler.get_traits()
print(json.dumps(traits, indent=4))
