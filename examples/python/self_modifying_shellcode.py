#!/usr/bin/env python

from binlex import Architecture, Configuration
from binlex.assemblers import Assembler
from binlex.controlflow import Graph
from binlex.disassemblers import Disassembler
from binlex.formats import Image, ImagePermissions, ImageSegment
from binlex.irs.lir import (
    LirBlock,
    LirCpuAmd64,
    LirExecutor,
    LirExecutorState,
    LirFunction,
    LirModule,
    LirStatus,
)


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

image = Image(
    [
        ImageSegment(
            name="shellcode",
            virtual_address=0,
            data=image_bytes,
            permissions=ImagePermissions.executable(),
        )
    ]
)

graph = Graph(architecture, image, configuration)
disassembler = Disassembler(graph)

instructions = disassembler.disassemble_block(0).instructions()

tail_address = instructions[-1].fallthrough()

assert tail_address

tail_instructions = disassembler.disassemble_block(tail_address).instructions()

payload_address = tail_instructions[-1].address() + len(tail_instructions[-1].bytes())
instructions.extend(tail_instructions)

lir_module = LirModule(name="self_modifying_shellcode")
lir_function = LirFunction(name="entry")
lir_block = LirBlock(name="entry")
for instruction in instructions:
    instruction_lir = instruction.lir()
    assert instruction_lir.status() == LirStatus.Complete
    lir_block.append_instruction(instruction_lir)
lir_function.append_block(lir_block)
lir_module.append_function(lir_function)

executor = LirExecutor()
executor.set_breakpoint(payload_address)

state = LirExecutorState(LirCpuAmd64())
state.map_memory(0, len(image_bytes))
state.write_memory(0, image_bytes)
state.set_register("rip", 64, 0)

decrypted_states = executor.run(lir_module, state)
executor.clear_breakpoints()

assert decrypted_states

decrypted_image_bytes = decryptor_code + payload_code

decrypted_image = Image(
    [
        ImageSegment(
            name="decrypted_shellcode",
            virtual_address=0,
            data=decrypted_image_bytes,
            permissions=ImagePermissions.executable(),
        )
    ]
)
decrypted_graph = Graph(architecture, decrypted_image, configuration)
stage2_instructions = Disassembler(decrypted_graph).disassemble_block(payload_address).instructions()

print("Shellcode Decryption Routine")
for instruction in instructions:
    print(f"  0x{instruction.address():x}: {instruction.disassembly()}")

print("Decrypted Self-Modifying Shellcode")
for instruction in stage2_instructions:
    print(f"  0x{instruction.address():x}: {instruction.disassembly()}")
