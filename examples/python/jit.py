#!/usr/bin/env python

import ctypes
from binlex.irs.lir import (
    LirModule,
    LirBlock,
    LirFunction,
    LirAbiLinuxSyscall,
    LirAbiSysv,
    LirCpuAmd64,
    Lir,
    LirEffect,
    LirExpression,
    LirLocation,
    LirOperationBinary,
    LirOperationCast,
    LirStatus,
    LirTerminator,
    LirTrapKind,
    LirExecutor,
    LirExecutorState,
)
from binlex.irs.llvm import LlvmModule

cpu = LirCpuAmd64()
sysv = LirAbiSysv(cpu)
linux_syscall = LirAbiLinuxSyscall(cpu)

add_two_semantics = LirModule(name="add_two")
add_two_function = LirFunction(name="add_two", abi=sysv)
add_two_block = LirBlock(name="entry")
add_two_block.append_instruction(
    Lir(
            version=1,
            status=LirStatus.Complete,
            effects=[
                LirEffect.set(
                    LirLocation.register("rax", 64),
                    LirExpression.binary(
                        LirOperationBinary.Add,
                        LirExpression.read(
                            LirLocation.register("rdi", 64)
                        ),
                        LirExpression.read(
                            LirLocation.register("rsi", 64)
                        ),
                        64
                    )
                )
            ],
                            terminator=LirTerminator.return_()
    )
)
add_two_function.append_block(add_two_block)
add_two_semantics.append_function(add_two_function)

write_semantics = LirModule(name="write")
write_function = LirFunction(name="write", abi=linux_syscall)
write_block = LirBlock(name="entry")
write_block.append_instruction(
    Lir(
            version=1,
            status=LirStatus.Complete,
            abi=linux_syscall,
            effects=[
                LirEffect.set(
                    LirLocation.stack_memory("stack", 8, 64),
                    LirExpression.read(
                        LirLocation.register("rdi", 64)
                    )
                ),
                LirEffect.set(
                    LirLocation.stack_memory("stack", 0, 8),
                    LirExpression.cast(
                        LirOperationCast.Truncate,
                        LirExpression.binary(
                            LirOperationBinary.Add,
                            LirExpression.read(
                                LirLocation.register("rdi", 64)
                            ),
                            LirExpression.const(48, 64),
                            64
                        ),
                        8
                    )
                ),
                LirEffect.set(
                    LirLocation.stack_memory("stack", 1, 8),
                    LirExpression.const(10, 8)
                ),
                LirEffect.set(
                    LirLocation.register("rax", 64),
                    LirExpression.const(1, 64)
                ),
                LirEffect.set(
                    LirLocation.register("rdi", 64),
                    LirExpression.const(1, 64)
                ),
                LirEffect.set(
                    LirLocation.register("rsi", 64),
                    LirExpression.address_of(
                        LirLocation.stack_memory("stack", 0, 8),
                        64
                    )
                ),
                LirEffect.set(
                    LirLocation.register("rdx", 64),
                    LirExpression.const(2, 64)
                ),
                LirEffect.trap(LirTrapKind.Syscall),
                LirEffect.set(
                    LirLocation.register("rax", 64),
                    LirExpression.read(
                        LirLocation.stack_memory("stack", 8, 64)
                    )
                ),
            ],
                            terminator=LirTerminator.return_()
    )
)
write_function.append_block(write_block)
write_semantics.append_function(write_function)

executor = LirExecutor()

state = LirExecutorState(cpu)
state.set_register("rdi", 64, 1)
state.set_register("rsi", 64, 1)

states = executor.run(add_two_semantics, state)

assert len(states) > 0

result = states[0].evaluate_register("rax", 64)

assert result == 2

lifter = LlvmModule("jit_example", cpu)
fn_add_two = lifter.create_function("add_two", abi=sysv)
fn_add_two.set_lir(add_two_semantics)
fn_add_two.optimize_cfg()
fn_add_two.optimize_mem2reg()
fn_add_two.optimize_sroa()
fn_add_two.optimize_instcombine()
fn_add_two.optimize_gvn()
fn_add_two.optimize_dce()

add_two = fn_add_two.jit(
    return_type=ctypes.c_uint64,
    parameter_types=[ctypes.c_uint64, ctypes.c_uint64],
)

assert add_two

sum = add_two(1, 1)

assert sum == 2

fn_write = lifter.create_function("write", abi=sysv)
fn_write.set_lir(write_semantics)
fn_write.optimize_cfg()
fn_write.optimize_mem2reg()
fn_write.optimize_sroa()
fn_write.optimize_instcombine()
fn_write.optimize_gvn()
fn_write.optimize_dce()

write = fn_write.jit(
    return_type=ctypes.c_uint64,
    parameter_types=[ctypes.c_uint64],
)

assert write

lifter.optimize_cfg()
lifter.optimize_mem2reg()
lifter.optimize_sroa()
lifter.optimize_instcombine()
lifter.optimize_gvn()
lifter.optimize_dce()
lifter.print()

write(sum)
