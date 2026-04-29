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

use crate::Architecture;
use crate::semantics::{
    InstructionEncoding, InstructionSemantics, SemanticAddressSpace, SemanticDiagnostic,
    SemanticDiagnosticKind, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticOperationUnary, SemanticStatus, SemanticTerminator,
};
use capstone::Insn;
use capstone::RegId;
use capstone::arch::ArchOperand;
use capstone::arch::arm64::{Arm64OperandType, Arm64Reg, Arm64Shift, Arm64Vas};

#[path = "common/flags.rs"]
mod flags_helpers;
#[path = "common/addressing.rs"]
mod addressing_helpers;
#[path = "common/intrinsics.rs"]
mod intrinsic_helpers;
#[path = "common/operands.rs"]
mod operand_helpers;
#[path = "common/shared.rs"]
mod shared_helpers;
#[path = "common/vector/mod.rs"]
mod vector_helpers;

pub(in crate::semantics::capstone::arm64) use flags_helpers::*;
pub(in crate::semantics::capstone::arm64) use addressing_helpers::*;
pub(in crate::semantics::capstone::arm64) use intrinsic_helpers::*;
pub(in crate::semantics::capstone::arm64) use operand_helpers::*;
pub(in crate::semantics::capstone::arm64) use shared_helpers::*;
pub(in crate::semantics::capstone::arm64) use vector_helpers::*;

pub(super) fn leading_register_outputs(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Vec<SemanticLocation> {
    let mut outputs = Vec::new();
    for operand in operands {
        if let Some(location) = operand_location(machine, operand) {
            match location {
                SemanticLocation::Register { .. } => outputs.push(location),
                _ => break,
            }
        } else if matches!(operand, ArchOperand::Arm64Operand(_)) {
            break;
        }
    }
    outputs
}
