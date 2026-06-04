#!/usr/bin/env python

from binlex import Architecture, Assembler, Configuration, Disassembler
from binlex.controlflow import Graph
from binlex.formats import ELF
from binlex.irs.lir import LirAbiStdcall, LirCpuI386, LirModule
from binlex.irs.llvm import LlvmModule

configuration = Configuration()
cpu = LirCpuI386()

assembler = Assembler(Architecture.I386, configuration)

data = assembler.assemble(
    0x00,
    (
        "xor eax, eax;"
        " not eax;"
        " not eax;"
        " add eax, 0x30;"
        " sub eax, 0x18;"
        " mov ebx, 7;"
        " sub ebx, 2;"
        " add eax, ebx;"
        " xor ecx, ecx;"
        " add ecx, 0x11;"
        " sub eax, ecx;"
        " inc eax;"
        " dec eax;"
        " lea eax, [eax + 4];"
        " sub eax, 4;"
        " or eax, 0;"
        " ret"
    ),
)

graph = Graph(Architecture.I386, configuration)

disassembler = Disassembler(Architecture.I386, data, {0: len(data)}, configuration)

function = disassembler.disassemble_function(0x00, graph)
print("Polymorphic Shellcode")
for block in function.blocks():
    for instruction in block.instructions():
        print(f"{hex(instruction.address())}: {instruction.disassembly()}")

module = LirModule(name="polymorphic_shellcode")
module.append_function(function.lir())

llvm = LlvmModule(module.name(), cpu, triple="i386-unknown-unknown")
llvm.set_abi(LirAbiStdcall(cpu))
llvm.from_lir(module, configuration)
llvm.optimize_cfg()
llvm.optimize_gvn()
llvm.optimize_instcombine()
llvm.optimize_dce()

obj = llvm.object()

assert obj

elf = ELF(obj, configuration)

start = elf.symbol_name_to_file_offset(function.lir().name() or "function_0")

assert start is not None

disassembler = Disassembler(elf.architecture(), elf.bytes(), {start: elf.size()}, configuration)

graph = Graph(elf.architecture(), configuration)

function = disassembler.disassemble_function(start, graph)

print("Deobfuscated Polymorphic Shellcode")
for block in function.blocks():
    for instruction in block.instructions():
        print(f"{hex(instruction.address())}: {instruction.disassembly()}")
