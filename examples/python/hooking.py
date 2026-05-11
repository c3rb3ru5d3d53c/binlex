#!/usr/bin/env python

from typing import cast

from binlex import Architecture, Configuration
from binlex.assemblers import Assembler, AssemblerBackend
from binlex.controlflow import Graph
from binlex.disassemblers.capstone import Disassembler
from binlex.semantics import Semantic, SemanticCpu, Semantics
from binlex.symbolic import Executor, CpuState


def hook_code(_: int, state: CpuState):
    esp = state.evaluate_register("esp", 32)
    assert esp is not None
    return_address = state.evaluate_memory(esp, 4)
    message_pointer = state.evaluate_memory(esp + 4, 4)
    assert return_address is not None
    assert message_pointer is not None
    message_bytes = bytearray()
    offset = 0
    while True:
        byte = state.read_memory(message_pointer + offset, 1)
        assert byte is not None
        if byte == b"\x00":
            break
        message_bytes.extend(byte)
        offset += 1

    print(message_bytes.decode("utf-8"))
    state.set_register("eip", 32, return_address)
    state.set_register("esp", 32, esp + 4)
    return [state]


code_address = 0x0
stack_address = 0x7000
stack_size = 0x1000
message_address = 0x2000
message = b"hello world\x00"

config = Configuration()
assembler = Assembler(Architecture.I386, config, AssemblerBackend.Default)
program = assembler.assemble(
    code_address,
    """
    push 0x2000
    call host_print
    add esp, 4
    mov eax, 1
host_print:
    ret
    """,
)

disassembler = Disassembler(
    Architecture.I386,
    program,
    {code_address: len(program)},
    config,
)

graph = Graph(Architecture.I386, config)
disassembler.disassemble({code_address}, graph)

instructions = graph.instructions()
instructions.sort(key=lambda instruction: instruction.address())
assert instructions
raw_semantics = [instruction.semantic() for instruction in instructions]
assert all(semantic is not None for semantic in raw_semantics)
semantics = Semantics(cast(list[Semantic], raw_semantics))

host_print_address = instructions[-1].address()

cpu = SemanticCpu.i386()
state = CpuState(cpu)
executor = Executor()
state.map_memory(stack_address, stack_size)
state.map_memory(message_address, 0x1000)
state.write_memory(message_address, message)

initial_esp = stack_address + stack_size - 4
state.set_register("esp", 32, initial_esp)
state.set_register("eip", 32, code_address)
state.write_memory(initial_esp - 4, message_address.to_bytes(4, "little"))

executor.add_hook(host_print_address, hook_code)
states = executor.run(semantics, state)
assert len(states) == 1

final_state = states[0]
final_eax = final_state.evaluate_register("eax", 32)
final_eip = final_state.evaluate_register("eip", 32)
final_esp = final_state.evaluate_register("esp", 32)
assert final_eax == 1
print(f"final eax={final_eax} eip=0x{final_eip:08x} esp=0x{final_esp:08x}")
