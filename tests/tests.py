#!/usr/bin/env python

import sys
import json
from pprint import pprint
from hashlib import sha256
import pybinlex

raw = pybinlex.Raw()
result = raw.read_file('../tests/raw/raw.x86')
if result is False:
    print("[x] failed to read raw.x86")
    sys.exit(1)
raw_sections = raw.get_sections()
pprint(raw_sections)

pe = pybinlex.PE()
pe.setup(pybinlex.MACHINE_TYPES.IMAGE_FILE_MACHINE_I386)
result = pe.read_file('../tests/pe/pe.x86')
if result is False:
    print("[x] failed to read pe.x86")
    sys.exit(1)
pe_sections = pe.get_sections()
pprint(pe_sections)

elf = pybinlex.ELF()
elf.setup(pybinlex.ARCH.EM_386)
result = elf.read_file('../tests/elf/elf.x86')
if result is False:
    print("[x] failed to read elf.x86")
    sys.exit(1)
elf_sections = elf.get_sections()
pprint(elf_sections)

decompiler = pybinlex.Decompiler(raw)
decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32)
decompiler.append_queue({0}, pybinlex.DECOMPILER_OPERAND_TYPE.DECOMPILER_OPERAND_TYPE_FUNCTION, 0)
decompiler.decompile(raw_sections[0]['data'], raw_sections[0]['offset'], 0)
traits = decompiler.get_traits()
print(json.dumps(traits, indent=4))

decompiler = pybinlex.Decompiler(elf)
decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32)
for i in range(0, len(elf_sections)):
    decompiler.append_queue(elf_sections[i]['functions'], pybinlex.DECOMPILER_OPERAND_TYPE.DECOMPILER_OPERAND_TYPE_FUNCTION, i)
    decompiler.decompile(elf_sections[i]['data'], elf_sections[i]['offset'], i)
traits = decompiler.get_traits()
print(json.dumps(traits, indent=4))

decompiler = pybinlex.Decompiler(pe)
decompiler.setup(pybinlex.cs_arch.CS_ARCH_X86, pybinlex.cs_mode.CS_MODE_32)
for i in range(0, len(pe_sections)):
    decompiler.append_queue(pe_sections[i]['functions'], pybinlex.DECOMPILER_OPERAND_TYPE.DECOMPILER_OPERAND_TYPE_FUNCTION, i)
    decompiler.decompile(pe_sections[i]['data'], pe_sections[i]['offset'], i)
traits = decompiler.get_traits()
print(json.dumps(traits, indent=4))
