#!/usr/bin/env python

from binlex import Architecture, Configuration
from binlex.assemblers import Assembler
from binlex.controlflow import Graph
from binlex.disassemblers import Disassembler
from binlex.semantics import SemanticCpu, SemanticStatus, Semantics
from binlex.symbolic import CpuState, Executor


configuration = Configuration()
architecture = Architecture.AMD64
assembler = Assembler(architecture, configuration)

stage2_code = assembler.assemble(
    0,
    """
    mov eax, 0x44434241
    ret
    """,
)

xor_key = 0x55
payload_code = stage2_code

decryptor_template = """
mov esi, {payload_address}
mov ecx, {payload_size}
decrypt_loop:
    xor byte ptr [rsi], {xor_key}
    inc rsi
    dec ecx
    jne decrypt_loop
    sub rsi, {payload_size}
    jmp rsi
"""

decryptor_preview = assembler.assemble(
    0,
    decryptor_template.format(
        payload_address=0,
        payload_size=len(payload_code),
        xor_key=xor_key,
    ),
)

payload_address = len(decryptor_preview)

decryptor_code = assembler.assemble(
    0,
    decryptor_template.format(
        payload_address=payload_address,
        payload_size=len(payload_code),
        xor_key=xor_key,
    ),
)

encrypted_payload_code = (
    bytes(byte ^ xor_key for byte in payload_code)
)

image_bytes = decryptor_code + encrypted_payload_code

disassembler = Disassembler(architecture, image_bytes, {0: len(image_bytes)}, configuration)
graph = Graph(architecture, configuration)

instructions = disassembler.disassemble_block(0, graph).instructions()

tail_address = instructions[-1].fallthrough()

assert tail_address

tail_instructions = disassembler.disassemble_block(tail_address, graph).instructions()

payload_address = tail_instructions[-1].address() + len(tail_instructions[-1].bytes())
instructions.extend(tail_instructions)

semantics = Semantics()
for instruction in instructions:
    semantic = instruction.semantic()
    assert semantic is not None
    assert semantic.status() == SemanticStatus.Complete
    semantics.append_semantic(semantic)

executor = Executor()
executor.set_breakpoint(payload_address)

state = CpuState(SemanticCpu.amd64())
state.map_memory(0, len(image_bytes))
state.write_memory(0, image_bytes)
state.set_register("rip", 64, 0)

decrypted_states = executor.run(semantics, state)
executor.clear_breakpoints()

assert decrypted_states

decrypted_image_bytes = decryptor_code + payload_code

stage2_instructions = Disassembler(
    architecture,
    decrypted_image_bytes,
    {0: len(decrypted_image_bytes)},
    configuration,
).disassemble_block(payload_address, Graph(architecture, configuration)).instructions()

print("Shellcode Decryption Routine")
for instruction in instructions:
    print(f"  0x{instruction.address():x}: {instruction.disassembly()}")

print("Decrypted Self-Modifying Shellcode")
for instruction in stage2_instructions:
    print(f"  0x{instruction.address():x}: {instruction.disassembly()}")
