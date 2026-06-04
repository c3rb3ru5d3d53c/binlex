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

pub mod instruction;
pub mod normalize;
pub mod validate;

pub use instruction::{
    LirAddressSpace, LirBlock, LirData, LirDiagnostic, LirDiagnosticKind, LirEffect,
    LirEffectAtomicCmpXchg, LirEffectFence, LirEffectIntrinsic, LirEffectKind, LirEffectMemoryCopy,
    LirEffectMemorySet, LirEffectNop, LirEffectPop, LirEffectPush, LirEffectSet, LirEffectStore,
    LirEffectTrap, LirEffectWriteElement, LirEffectWriteProperty, LirEncoding, LirExpression,
    LirExpressionAddressOf, LirExpressionAllocate, LirExpressionBinary, LirExpressionCast,
    LirExpressionCompare, LirExpressionConcat, LirExpressionConst, LirExpressionDataAddress,
    LirExpressionExtract, LirExpressionFunction, LirExpressionIntrinsic, LirExpressionKind,
    LirExpressionLoad, LirExpressionNull, LirExpressionPoison, LirExpressionRead,
    LirExpressionReadElement, LirExpressionReadProperty, LirExpressionSelect, LirExpressionUnary,
    LirExpressionUndefined, LirFenceKind, LirFunction, LirInstruction, LirLocation,
    LirLocationFlag, LirLocationIndexedMemory, LirLocationKind, LirLocationMemory,
    LirLocationProgramCounter, LirLocationRegister, LirLocationStackMemory, LirLocationTemporary,
    LirMetadata, LirModule, LirOperation, LirOperationBinary, LirOperationCast,
    LirOperationCompare, LirOperationUnary, LirStatus, LirTemporary, LirTerminator,
    LirTerminatorBranch, LirTerminatorCall, LirTerminatorFallThrough, LirTerminatorJump,
    LirTerminatorKind, LirTerminatorReturn, LirTerminatorTrap, LirTerminatorUnreachable,
    LirTrapKind,
};
pub use normalize::normalize_instruction_lir;
pub use validate::validate_instruction_lir;
