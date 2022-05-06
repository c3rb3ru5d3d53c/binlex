#!/usr/bin/env python

import json
from pprint import pprint
from hashlib import sha256
import pybinlex

raw = pybinlex.Raw()
raw.read_file('tests/raw/raw.x86')
raw_sections = raw.get_sections()
pprint(raw_sections)

pe = pybinlex.PE()
pe.setup(pybinlex.MACHINE_TYPES.IMAGE_FILE_MACHINE_I386)
pe.read_file('tests/pe/pe.x86')
pe_sections = pe.get_sections()
pprint(pe_sections)

elf = pybinlex.ELF()
elf.setup(pybinlex.ARCH.EM_386)
elf.read_file('tests/elf/elf.x86')
elf_sections = elf.get_sections()
pprint(elf_sections)

decompiler = pybinlex.Decompiler(raw)
decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32, 0)
decompiler.decompile(raw_sections[0]['data'], raw_sections[0]['offset'], 0)
traits = decompiler.get_traits()
print(json.dumps(traits, indent=4))
