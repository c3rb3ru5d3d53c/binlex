#!/usr/bin/env python

import ctypes
from binlex import Configuration
from binlex.semantics import (
    SemanticAbi,
    SemanticCpu,
    Semantic,
    SemanticEffect,
    SemanticExpression,
    SemanticLocation,
    SemanticOperationBinary,
    SemanticOperationCast,
    SemanticStatus,
    SemanticTerminator,
    SemanticTrapKind,
)
from binlex.symbolic import Executor, CpuState
from binlex.lifters import Lifter

configuration = Configuration()

cpu = SemanticCpu.amd64()
sysv = SemanticAbi.sysv(cpu)
linux_syscall = SemanticAbi.linux_syscall(cpu)

add_two_semantics = [
    Semantic(
        version=1,
        status=SemanticStatus.Complete,
        effects=[
            SemanticEffect.set(
                SemanticLocation.register("rax", 64),
                SemanticExpression.binary(
                    SemanticOperationBinary.Add,
                    SemanticExpression.read(
                        SemanticLocation.register("rdi", 64)
                    ),
                    SemanticExpression.read(
                        SemanticLocation.register("rsi", 64)
                    ),
                    64
                )
            )
        ],
        terminator=SemanticTerminator.return_()
    )
]

write_semantics = [
    Semantic(
        version=1,
        status=SemanticStatus.Complete,
        abi=linux_syscall,
        effects=[
            SemanticEffect.set(
                SemanticLocation.stack_memory("stack", 8, 64),
                SemanticExpression.read(
                    SemanticLocation.register("rdi", 64)
                )
            ),
            SemanticEffect.set(
                SemanticLocation.stack_memory("stack", 0, 8),
                SemanticExpression.cast(
                    SemanticOperationCast.Truncate,
                    SemanticExpression.binary(
                        SemanticOperationBinary.Add,
                        SemanticExpression.read(
                            SemanticLocation.register("rdi", 64)
                        ),
                        SemanticExpression.const(48, 64),
                        64
                    ),
                    8
                )
            ),
            SemanticEffect.set(
                SemanticLocation.stack_memory("stack", 1, 8),
                SemanticExpression.const(10, 8)
            ),
            SemanticEffect.set(
                SemanticLocation.register("rax", 64),
                SemanticExpression.const(1, 64)
            ),
            SemanticEffect.set(
                SemanticLocation.register("rdi", 64),
                SemanticExpression.const(1, 64)
            ),
            SemanticEffect.set(
                SemanticLocation.register("rsi", 64),
                SemanticExpression.address_of(
                    SemanticLocation.stack_memory("stack", 0, 8),
                    64
                )
            ),
            SemanticEffect.set(
                SemanticLocation.register("rdx", 64),
                SemanticExpression.const(2, 64)
            ),
            SemanticEffect.trap(SemanticTrapKind.Syscall),
            SemanticEffect.set(
                SemanticLocation.register("rax", 64),
                SemanticExpression.read(
                    SemanticLocation.stack_memory("stack", 8, 64)
                )
            ),
        ],
        terminator=SemanticTerminator.return_()
    )
]

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
    restype=ctypes.c_uint64,
    argtypes=[ctypes.c_uint64, ctypes.c_uint64],
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
    restype=ctypes.c_uint64,
    argtypes=[ctypes.c_uint64],
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
