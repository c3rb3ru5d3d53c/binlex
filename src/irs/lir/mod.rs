// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

pub mod abis;
pub mod arm64;
pub mod cil;
pub mod cpus;
pub mod executor;
pub mod ir;
pub mod mlir;
pub mod optimizers;
pub mod print;
pub mod x86;

pub use abis::{
    LirAbi, LirAbiCdecl, LirAbiFastcall, LirAbiKind, LirAbiLinuxSyscall, LirAbiStdcall, LirAbiSysv,
    LirAbiTrap, LirAbiWindows64, LirAbiWindowsSyscall,
};
pub use cpus::{
    LirCpu, LirCpuAlias, LirCpuAliasWritePolicy, LirCpuAmd64, LirCpuArm64, LirCpuCil, LirCpuEndian,
    LirCpuI386, LirCpuKind, LirCpuProgramCounter, LirCpuRegister, LirMemory, LirMemoryAddressed,
    LirMemoryIndexed, LirMemoryStack,
};
pub use executor::{
    LirExecutor, LirExecutorError, LirExecutorState, Slice, SliceInstruction, SliceNode,
};
pub use ir::{
    Lir, LirAddressSpace, LirBlock, LirData, LirDiagnostic, LirDiagnosticKind, LirEffect,
    LirEffectKind, LirEncoding, LirExpression, LirExpressionKind, LirFenceKind, LirFunction,
    LirLocation, LirLocationKind, LirMetadata, LirModule, LirOperation, LirOperationBinary,
    LirOperationCast, LirOperationCompare, LirOperationUnary, LirStatus, LirTemporary,
    LirTerminator, LirTerminatorKind, LirTrapKind, normalize_instruction_lir,
    validate_instruction_lir,
};
pub use mlir::LirMlirModule;
pub use optimizers::{
    optimize, optimize_branches, optimize_casts, optimize_constants, optimize_identities,
    optimize_intrinsics, optimize_noops,
};
pub use print::{format_lir_block, format_lir_function, format_lir_instruction, format_lir_module};
