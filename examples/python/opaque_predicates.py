#!/usr/bin/env python3

import binlex
from binlex.controlflow import Graph
from binlex.disassemblers import Disassembler
from binlex.symbolic import Executor


architecture = binlex.Architecture.I386

# xor eax, eax
# test eax, eax
# jne 0x1008
# nop
# nop
# ret
shellcode = bytes.fromhex("31c085c075029090c3")

config = binlex.Config()

graph = Graph(architecture, config)
disassembler = Disassembler(
    architecture,
    shellcode,
    {0: len(shellcode)},
    config,
)

disassembler.disassemble_function(0x00, graph)

function = graph.get_function(0x00)

assert function, 'failed to disassemble function'

executor = Executor(architecture)
state = executor.state()

for block in function.blocks():
    for instruction in block.instructions():
        print(f"{hex(instruction.address())}: {instruction.disassembly()}")

        semantics = instruction.semantics()

        if semantics is None:
            continue

        successors = executor.step(semantics, state)

        states = [successor for successor in successors if successor.satisfiable()]

        if not states:
            continue

        if len(successors) < 2:
            state = states[0]
            continue

        if len(states) != 1:
            continue

        target = states[0].evaluate_register("eip", 32)

        if target is None:
            continue

        print(f"{instruction.address():#x}: {instruction.disassembly()} -> {target:#x}")
