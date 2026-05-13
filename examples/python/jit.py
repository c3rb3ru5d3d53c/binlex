#!/usr/bin/env python

import ctypes
from binlex import Configuration
from binlex.ir.lir import (
    LirModule,
    LirAbi,
    LirCpu,
    Lir,
    LirEffect,
    LirExpression,
    LirLocation,
    LirOperationBinary,
    LirOperationCast,
    LirStatus,
    LirTerminator,
    LirTrapKind,
)
from binlex.symbolic import Executor, CpuState
from binlex.lifters import Lifter

configuration = Configuration()

cpu = LirCpu.amd64()
sysv = LirAbi.sysv(cpu)
linux_syscall = LirAbi.linux_syscall(cpu)

add_two_semantics = LirModule(
    semantics=[
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
    ]
)

write_semantics = LirModule(
    semantics=[
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
    ]
)

executor = Executor()

state = CpuState(cpu)
state.set_register("rdi", 64, 1)
state.set_register("rsi", 64, 1)

states = executor.run(add_two_semantics, state)

assert len(states) > 0

result = states[0].evaluate_register("rax", 64)

assert result == 2

lifter = Lifter(cpu, configuration)
fn_add_two = lifter.create_function("add_two", abi=sysv)
fn_add_two.lift_function_semantics(add_two_semantics)
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
fn_write.lift_function_semantics(write_semantics)
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
