use crate::Architecture;
use crate::semantics::InstructionSemantics;
use capstone::Insn;
use capstone::arch::ArchOperand;

use super::builders;
use super::common::unsupported_fallthrough;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> InstructionSemantics {
    if let Some(semantics) = builders::control::build(instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::integer::build(machine, instruction, operands, condition_code)
    {
        return semantics;
    }
    if let Some(semantics) = builders::multiply::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::fp::build(machine, instruction, operands, condition_code) {
        return semantics;
    }
    if let Some(semantics) = builders::memory::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::atomic::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::system::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::vector::build(machine, instruction, operands, condition_code)
    {
        return semantics;
    }
    unsupported_fallthrough(machine, instruction, "arm64 mnemonic not implemented")
}
