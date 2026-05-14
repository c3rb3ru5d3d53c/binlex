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
pub mod ir;
pub mod optimizers;
pub mod print;
pub mod x86;

pub use abis::{LirAbi, LirAbiKind, LirAbiTrap};
pub use cpus::{
    LirCpu, LirCpuAlias, LirCpuAliasWritePolicy, LirCpuEndian, LirCpuKind, LirCpuProgramCounter,
    LirCpuRegister, LirMemory, LirMemoryAddressed, LirMemoryIndexed, LirMemoryStack,
};
pub use ir::{
    Lir, LirAddressSpace, LirData, LirDiagnostic, LirDiagnosticKind, LirEffect, LirEffectKind,
    LirEncoding, LirExpression, LirExpressionKind, LirFenceKind, LirJson, LirLocation,
    LirLocationKind, LirModule, LirOperation, LirOperationBinary, LirOperationCast,
    LirOperationCompare, LirOperationUnary, LirStatus, LirTemporary, LirTerminator,
    LirTerminatorKind, LirTrapKind, normalize_instruction_lir, validate_instruction_lir,
};
pub use optimizers::{
    optimize_branches, optimize_casts, optimize_constants, optimize_identities,
    optimize_intrinsics, optimize_noops, optimize_simplify,
};
pub use print::{format_lir, format_lir_module};
