#!/usr/bin/env python3

from binlex import Architecture
from binlex.config import Config
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.symbolic import Executor


function_address = 0x40056D
target_offset = 0x41

input_address = 0x1000
serial_pointer_address = 0x601040
serial_data_address = 0x900000
stack_top = 0x7FFFFFFF

shellcode = bytes.fromhex(
    "55"
    "4889e5"
    "48897de8"
    "c745fc00000000"
    "eb3f"
    "8b45fc"
    "4863d0"
    "488b45e8"
    "4801d0"
    "0fb600"
    "0fbec0"
    "83e801"
    "83f055"
    "89c1"
    "488b15a00a2000"
    "8b45fc"
    "4898"
    "4801d0"
    "0fb600"
    "0fbec0"
    "39c1"
    "7407"
    "b801000000"
    "eb0f"
    "8345fc01"
    "837dfc04"
    "7ebb"
    "b800000000"
    "5d"
    "c3"
)
def main():
    config = Config()
    config.semantics.enabled = True

    graph = Graph(Architecture.AMD64, config)
    disassembler = Disassembler(
        Architecture.AMD64,
        shellcode,
        {0: len(shellcode)},
        config,
    )
    disassembler.disassemble_function(0, graph)
    function = graph.functions()[0]

    executor = Executor(Architecture.AMD64)
    state = executor.state()

    state.map_memory(input_address, 5)
    state.symbolize_memory(input_address, 5, "input")

    state.map_memory(serial_pointer_address, 8)
    state.write_memory(serial_pointer_address, serial_data_address.to_bytes(8, "little"))

    state.map_memory(serial_data_address, 5)
    state.write_memory(serial_data_address, bytes([0x31, 0x3E, 0x3D, 0x26, 0x31]))

    state.map_memory(stack_top - 0x1000, 0x2000)

    state.set_register("rdi", 64, input_address)
    state.set_register("rsp", 64, stack_top)
    state.set_register("rbp", 64, stack_top)

    done = False
    for block in function.blocks():
        for instruction in block.instructions():
            semantics = instruction.semantics()
            pc = instruction.address()

            state.set_register("rip", 64, pc)
            states = executor.step(semantics, state)

            if len(states) == 1:
                state = states[0]
            else:
                state = [candidate for candidate in states if candidate.satisfiable()][0]

            next_pc = state.evaluate_register("rip", 64)
            if next_pc == target_offset:
                done = True
                break
        if done:
            break

    slice_ = state.slice_from_register("ecx", 32)

    for node in slice_.nodes():
        instruction = node.instruction()
        if instruction is None:
            continue
        print(
            f"[slicing] {instruction.address() + function_address:#x}: "
            f"{instruction.disassembly()}"
        )


if __name__ == "__main__":
    main()
