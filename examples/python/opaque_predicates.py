#!/usr/bin/env python3

import binlex
from binlex.controlflow import Graph
from binlex.disassemblers import Disassembler
from binlex.semantics import SemanticCpu
from binlex.symbolic import CpuState, Executor


architecture = binlex.Architecture.I386

shellcode = bytes.fromhex("31c085c075029090c3")

config = binlex.Configuration()

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

cpu = SemanticCpu.i386()
executor = Executor()
state = CpuState(cpu)

for block in function.blocks():
    for instruction in block.instructions():
        print(f"{hex(instruction.address())}: {instruction.disassembly()}")

        semantics = instruction.semantic()

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
