use crate::Architecture;
use crate::semantics::InstructionSemantics;
use capstone::Insn;
use capstone::arch::ArchOperand;

use super::builders;
use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> InstructionSemantics {
    if let Some(semantics) = builders::control::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::stack::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::integer::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::logic::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::shift::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::bit::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::string::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::system::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::vector::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = builders::fp::build(machine, instruction, operands) {
        return semantics;
    }
    common::unsupported_fallthrough(instruction, "x86 mnemonic not implemented")
}
