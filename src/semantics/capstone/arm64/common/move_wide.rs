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

use super::*;

pub(in crate::semantics::capstone::arm64) fn build_move(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: src,
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_movk(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let mut current = SemanticExpression::Read(Box::new(dst.clone()));
    let mut immediate = None;
    let mut shift = 0u16;

    for operand in operands.iter().skip(1) {
        let ArchOperand::Arm64Operand(op) = operand else {
            continue;
        };
        match op.op_type {
            Arm64OperandType::Reg(_) => current = operand_expression(operand)?,
            Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => {
                if immediate.is_none() {
                    immediate = Some(imm as u64);
                    if let Arm64Shift::Lsl(value) = op.shift {
                        shift = value as u16;
                    }
                } else {
                    shift = imm as u16;
                }
            }
            _ => {}
        }
    }

    let immediate = immediate?;
    let field_mask = if shift >= bits {
        0
    } else {
        ((0xffffu64) << shift) & bitmask(bits)
    };
    let cleared = binary(
        SemanticOperationBinary::And,
        current,
        const_u64((!field_mask) & bitmask(bits), bits),
        bits,
    );
    let inserted = binary(
        SemanticOperationBinary::Shl,
        const_u64(immediate & 0xffff, bits),
        const_u64(shift as u64, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, cleared, inserted, bits),
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_movz(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let (immediate, shift) = parse_move_wide_immediate(operands.iter().skip(1), bits)?;
    let expression = binary(
        SemanticOperationBinary::Shl,
        const_u64(immediate & 0xffff, bits),
        const_u64(shift as u64, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_movn(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let (immediate, shift) = parse_move_wide_immediate(operands.iter().skip(1), bits)?;
    let inserted = binary(
        SemanticOperationBinary::Shl,
        const_u64(immediate & 0xffff, bits),
        const_u64(shift as u64, bits),
        bits,
    );
    let expression = binary(
        SemanticOperationBinary::Xor,
        inserted,
        const_u64(bitmask(bits), bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}
