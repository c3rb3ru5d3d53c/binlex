#!/usr/bin/env python

import ctypes
from binlex.irs.lir import (
    Lir,
    LirAbiLinuxSyscall,
    LirAbiSysv,
    LirBlock,
    LirCpuAmd64,
    LirEffectSet,
    LirEffectTrap,
    LirExpressionAddressOf,
    LirExpressionBinary,
    LirExpressionCast,
    LirExpressionConst,
    LirExpressionRead,
    LirFunction,
    LirLocationRegister,
    LirLocationStackMemory,
    LirModule,
    LirOperationBinary,
    LirOperationCast,
    LirStatus,
    LirTerminatorReturn,
    LirTrapKind,
    LirExecutor,
    LirExecutorState,
)
from binlex.irs.llvm import LlvmFunction, LlvmModule

cpu = LirCpuAmd64()
sysv = LirAbiSysv(cpu)
linux_syscall = LirAbiLinuxSyscall(cpu)

add_two_lir = LirModule(name="add_two")
add_two_function = LirFunction(name="add_two", abi=sysv)
add_two_block = LirBlock(name="entry")
add_two_block.append_instruction(
    Lir(
        version=1,
        status=LirStatus.Complete,
        effects=[
            LirEffectSet(
                LirLocationRegister("rax", 64),
                LirExpressionBinary(
                    LirOperationBinary.Add,
                    LirExpressionRead(LirLocationRegister("rdi", 64)),
                    LirExpressionRead(LirLocationRegister("rsi", 64)),
                    64,
                ),
            )
        ],
        terminator=LirTerminatorReturn(),
    )
)
add_two_function.append_block(add_two_block)
add_two_lir.append_function(add_two_function)

write_lir = LirModule(name="write")
write_function = LirFunction(name="write", abi=sysv)
write_block = LirBlock(name="entry")
write_block.append_instruction(
    Lir(
        version=1,
        status=LirStatus.Complete,
        abi=linux_syscall,
        effects=[
            LirEffectSet(
                LirLocationStackMemory("stack", 8, 64),
                LirExpressionRead(LirLocationRegister("rdi", 64)),
            ),
            LirEffectSet(
                LirLocationStackMemory("stack", 0, 8),
                LirExpressionCast(
                    LirOperationCast.Truncate,
                    LirExpressionBinary(
                        LirOperationBinary.Add,
                        LirExpressionRead(LirLocationRegister("rdi", 64)),
                        LirExpressionConst(48, 64),
                        64,
                    ),
                    8,
                ),
            ),
            LirEffectSet(
                LirLocationStackMemory("stack", 1, 8),
                LirExpressionConst(10, 8),
            ),
            LirEffectSet(
                LirLocationRegister("rax", 64),
                LirExpressionConst(1, 64),
            ),
            LirEffectSet(
                LirLocationRegister("rdi", 64),
                LirExpressionConst(1, 64),
            ),
            LirEffectSet(
                LirLocationRegister("rsi", 64),
                LirExpressionAddressOf(LirLocationStackMemory("stack", 0, 8), 64),
            ),
            LirEffectSet(
                LirLocationRegister("rdx", 64),
                LirExpressionConst(2, 64),
            ),
            LirEffectTrap(LirTrapKind.Syscall),
            LirEffectSet(
                LirLocationRegister("rax", 64),
                LirExpressionRead(LirLocationStackMemory("stack", 8, 64)),
            ),
        ],
        terminator=LirTerminatorReturn(),
    )
)
write_function.append_block(write_block)
write_lir.append_function(write_function)

executor = LirExecutor()

state = LirExecutorState(cpu)
state.set_register("rdi", 64, 1)
state.set_register("rsi", 64, 1)

states = executor.run(add_two_lir, state)

assert len(states) > 0

result = states[0].evaluate_register("rax", 64)

assert result == 2

lifter = LlvmModule("jit_example", cpu)
fn_add_two = LlvmFunction("add_two")
fn_add_two.set_lir(add_two_function)
lifter.append_function(fn_add_two)
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

fn_write = LlvmFunction("write")
fn_write.set_lir(write_function)
lifter.append_function(fn_write)
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
