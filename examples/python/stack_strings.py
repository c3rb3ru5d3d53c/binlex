#!/usr/bin/env python3

from binlex import Architecture
from binlex import Configuration
from binlex.assemblers import Assembler
from binlex.controlflow import Graph
from binlex.disassemblers import Disassembler
from binlex.semantics import SemanticCpu
from binlex.symbolic import SymbolicCpuState, SymbolicExecutor

assembly = """
sub esp, 32
mov dword ptr [esp], 0x737c6862
mov dword ptr [esp + 4], 0x72787d7e
mov dword ptr [esp + 8], 0x74697431
mov dword ptr [esp + 12], 0x78656472
mov dword ptr [esp + 16], 0x78317f7e
mov dword ptr [esp + 20], 0x747f3162
mov dword ptr [esp + 24], 0x3f306570
mov dword ptr [esp + 28], 0x3f3f3f3f
mov edi, esp
lea esi, [esp + 32]
decrypt_loop:
xor dword ptr [edi], 0x11111111
add edi, 4
cmp edi, esi
jne decrypt_loop
ret
"""

stack_base = 0x2000
stack_size = 0x1000

architecture = Architecture.I386

config = Configuration()

assembler = Assembler(architecture, config)

shellcode = assembler.assemble(0, assembly)

graph = Graph(architecture, config)

disassembler = Disassembler(
    architecture,
    shellcode,
    {0: len(shellcode)},
    config,
)
disassembler.disassemble_function(0, graph)

function = graph.get_function(0)

assert function, "failed"

cpu = SemanticCpu(architecture)
executor = SymbolicExecutor()
state = SymbolicCpuState(cpu)
state.set_register("esp", 32, stack_base)
state.map_memory(stack_base - stack_size, stack_size)

semantics = [
    semantics
    for block in function.blocks()
    for instruction in block.instructions()
    if (semantics := instruction.semantic()) is not None
]

states = executor.run(semantics, state)

live = [candidate for candidate in states if candidate.satisfiable()]

assert live, "state failed"

state = live[0]

esp = state.evaluate_register("esp", 32)

assert esp, "failed to evaludate stack register"

plaintext = state.read_memory(esp - 4, 32)

assert plaintext, "failed to read memory"

print(plaintext.rstrip(b"\x00").decode("ascii"))
