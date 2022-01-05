#!/usr/bin/env python

from pprint import pprint
from hashlib import sha256
import build.pybinlex as pybinlex

raw = pybinlex.Raw()
raw.read_file('tests/raw/raw.x86', 0)
sections = raw.get_sections()
pprint(sections)

pe = pybinlex.PE()
pe.setup(pybinlex.MACHINE_TYPES.IMAGE_FILE_MACHINE_I386)
pe.read_file('tests/pe/pe.x86')
sections = pe.get_sections()
pprint(sections)

elf = pybinlex.ELF()
elf.setup(pybinlex.ARCH.EM_386)
elf.read_file('tests/elf/elf.x86')
sections = elf.get_sections()
pprint(sections)

decompiler = pybinlex.Decompiler()
decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32, 0)
print(decompiler.decompile(b'HelloWorld'))