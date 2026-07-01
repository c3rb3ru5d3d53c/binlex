#!/usr/bin/env python

from binlex import Architecture, Assembler, Configuration, Disassembler
from binlex.controlflow import Graph
from binlex.formats import Image, ImagePermissions, ImageSegment
from binlex.irs.lir import LirCpuI386, LirModule
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

image = Image(
    [
        ImageSegment(
            name="shellcode",
            virtual_address=0,
            data=data,
            permissions=ImagePermissions.executable(),
        )
    ]
)

graph = Graph(Architecture.I386, image, configuration)

function = Disassembler(graph).disassemble_function(0x00)
print("Polymorphic Shellcode")
for block in function.blocks():
    for instruction in block.instructions():
        print(f"{hex(instruction.address())}: {instruction.disassembly()}")

module = LirModule(name="polymorphic_shellcode")
module.append_function(function.lir())

assert function.lir().bytecode()
assert function.lir().ssa().bytecode()

llvm = LlvmModule(module.name(), cpu, triple="i386-unknown-unknown")
llvm.from_lir(module, configuration)
llvm.optimize_cfg()
llvm.optimize_gvn()
llvm.optimize_instcombine()
llvm.optimize_dce()

print("Optimized LLVM IR")
print(llvm.text())
