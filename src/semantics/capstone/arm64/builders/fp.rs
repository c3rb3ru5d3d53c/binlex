use super::*;
use crate::semantics::{SemanticOperationCast, SemanticOperationUnary};
use capstone::arch::arm64::Arm64OperandType;

#[path = "fp/ops.rs"]
mod ops;

use ops::*;

pub(crate) fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    match instruction.mnemonic().unwrap_or("") {
        "fabs" => build_fabs(machine, operands),
        "fneg" => build_fneg(machine, operands),
        "fcmp" | "fcmpe" => build_fcmp_intrinsic(machine, operands),
        "fccmp" => build_fccmp(machine, operands, condition_code),
        "fadd" => build_fp_binary(machine, operands, SemanticOperationBinary::FAdd),
        "fsub" => build_fp_binary(machine, operands, SemanticOperationBinary::FSub),
        "fmul" => build_fp_binary(machine, operands, SemanticOperationBinary::FMul),
        "fdiv" => build_fp_binary(machine, operands, SemanticOperationBinary::FDiv),
        "fnmul" => build_fnmul(machine, operands),
        "fmadd" => build_fmadd(machine, operands),
        "fmsub" => build_fmsub(machine, operands),
        "scvtf" => build_scvtf(machine, operands),
        "ucvtf" => build_ucvtf(machine, operands),
        "fcvtzs" => build_fcvtzs(machine, operands),
        "fcvtzu" => build_fcvtzu(machine, operands),
        "fmin" => build_fp_minmax(machine, operands, SemanticOperationCompare::Olt),
        "fmax" => build_fp_minmax(machine, operands, SemanticOperationCompare::Ogt),
        _ => None,
    }
}
