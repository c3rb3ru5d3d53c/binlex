#!/usr/bin/env python3

import binlex
from binlex.controlflow import Graph
from binlex.disassemblers import Disassembler
from binlex.formats import Image, ImagePermissions, ImageSegment
from binlex.irs.lir import (
    LirBlock,
    LirCpuI386,
    LirExecutor,
    LirExecutorState,
    LirFunction,
    LirModule,
)


architecture = binlex.Architecture.I386

shellcode = bytes.fromhex("31c085c075029090c3")

config = binlex.Configuration()


def module_from_lir(lir):
    module = LirModule(name="instruction")
    function = LirFunction(name="instruction")
    block = LirBlock(name="entry")
    block.append_instruction(lir)
    function.append_block(block)
    module.append_function(function)
    return module

image = Image(
    [
        ImageSegment(
            name="shellcode",
            virtual_address=0,
            data=shellcode,
            permissions=ImagePermissions.executable(),
        )
    ]
)

graph = Graph(architecture, image, config)
disassembler = Disassembler(graph)
disassembler.disassemble_function(0x00)

function = graph.function(0x00)

assert function, 'failed to disassemble function'

cpu = LirCpuI386()
executor = LirExecutor()
state = LirExecutorState(cpu)

for block in function.blocks():
    for instruction in block.instructions():
        print(f"{hex(instruction.address())}: {instruction.disassembly()}")

        lir = instruction.lir()

        successors = executor.step(module_from_lir(lir), state)

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
