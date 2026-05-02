#!/usr/bin/env python3

import binlex
from binlex.controlflow import Graph, Instruction
from binlex.disassemblers import Disassembler
from binlex.symbolic import Executor


architecture = binlex.Architecture.I386
stack_base = 0x2000
stack_size = 0x1000

# push 0x747f7e75        ; encrypted "done"
# xor dword ptr [esp], 0x11111111
# push 0x65627465        ; encrypted "test"
# xor dword ptr [esp], 0x11111111
shellcode = bytes.fromhex(
    "68 75 7e 7f 74"
    "81 34 24 11 11 11 11"
    "68 65 74 62 65"
    "81 34 24 11 11 11 11"
)

config = binlex.Config()
config.instructions.enabled = True
config.semantics.enabled = True

graph = Graph(architecture, config)
disassembler = Disassembler(
    architecture,
    shellcode,
    {0: len(shellcode)},
    config,
)

pc = 0
instructions = []
while pc < len(shellcode):
    disassembler.disassemble_instruction(pc, graph)
    instruction = Instruction(pc, graph)
    instructions.append(instruction)
    pc += instruction.size()

executor = Executor(architecture)
state = executor.state()
state.set_register("esp", 32, stack_base)
state.map_memory(stack_base - stack_size, stack_size)

for instruction in instructions:
    semantics = instruction.semantics()
    if semantics is None:
        continue

    successors = executor.step(semantics, state)
    live = [successor for successor in successors if successor.satisfiable()]
    if not live:
        raise RuntimeError(f"path became infeasible at {instruction.address():#x}")
    state = live[0]

esp = state.evaluate_register("esp", 32)
if esp is None:
    raise RuntimeError("failed to concretize esp")

value = state.evaluate_memory(esp, 8)
if value is None:
    raise RuntimeError("failed to concretize decrypted stack string")

plaintext = value.to_bytes(8, "little")
recovered = plaintext.rstrip(b"\x00")
while recovered and not recovered.isascii():
    recovered = recovered[:-1]
recovered = recovered.decode("ascii")

print(f"decrypted stack string: {recovered}")
