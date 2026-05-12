#!/usr/bin/env python

from binlex import Architecture, Configuration
from binlex.controlflow import Graph
from binlex.assemblers import Assembler
from binlex.semantics import SemanticAbi, SemanticCpu
from binlex.disassemblers import Disassembler
from binlex.formats import ELF

configuration = Configuration()

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

cpu = SemanticCpu.i386()

function = disassembler.disassemble_function(0x00, graph)
print("Polymorphic Shellcode")
for block in function.blocks():
    for instruction in block.instructions():
        print(f"{hex(instruction.address())}: {instruction.disassembly()}")


llvm = function.lift(abi=SemanticAbi.stdcall(cpu))

assert llvm

llvm.set_name("_start")
llvm.optimize_cfg()
llvm.optimize_gvn()
llvm.optimize_instcombine()
llvm.optimize_dce()

obj = llvm.object()

assert obj

elf = ELF(obj, configuration)

start = elf.symbol_name_to_file_offset("_start")

assert start is not None

disassembler = Disassembler(elf.architecture(), elf.bytes(), {start: elf.size()}, configuration)

graph = Graph(elf.architecture(), configuration)

function = disassembler.disassemble_function(start, graph)

print("Deobfuscated Polymorphic Shellcode")
for block in function.blocks():
    for instruction in block.instructions():
        print(f"{hex(instruction.address())}: {instruction.disassembly()}")
