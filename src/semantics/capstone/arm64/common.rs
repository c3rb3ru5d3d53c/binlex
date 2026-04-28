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

pub(super) fn build_load_pair(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let first_dst = operand_location(machine, operands.first()?)?;
    let second_dst = operand_location(machine, operands.get(1)?)?;
    let base_addr = effective_memory_address(instruction, operands.get(2)?, operands.get(3))?;
    let stride = (first_dst.bits() / 8) as u64;
    let second_addr = binary(
        SemanticOperationBinary::Add,
        base_addr.clone(),
        const_u64(stride, 64),
        64,
    );

    let mut effects = vec![
        SemanticEffect::Set {
            dst: first_dst.clone(),
            expression: SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(base_addr),
                bits: first_dst.bits(),
            },
        },
        SemanticEffect::Set {
            dst: second_dst.clone(),
            expression: SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(second_addr),
                bits: second_dst.bits(),
            },
        },
    ];

    if let Some(writeback) = writeback_effect(instruction, operands.get(2)?, operands.get(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_store_pair(
    _machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let first_src = operand_expression(operands.first()?)?;
    let second_src = operand_expression(operands.get(1)?)?;
    let base_addr = effective_memory_address(instruction, operands.get(2)?, operands.get(3))?;
    let stride = (first_src.bits() / 8) as u64;
    let second_addr = binary(
        SemanticOperationBinary::Add,
        base_addr.clone(),
        const_u64(stride, 64),
        64,
    );

    let mut effects = vec![
        SemanticEffect::Store {
            space: SemanticAddressSpace::Default,
            addr: base_addr,
            expression: first_src.clone(),
            bits: first_src.bits(),
        },
        SemanticEffect::Store {
            space: SemanticAddressSpace::Default,
            addr: second_addr,
            expression: second_src.clone(),
            bits: second_src.bits(),
        },
    ];

    if let Some(writeback) = writeback_effect(instruction, operands.get(2)?, operands.get(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_load_pair_signed_word(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let first_dst = operand_location(machine, operands.first()?)?;
    let second_dst = operand_location(machine, operands.get(1)?)?;
    let base_addr = effective_memory_address(instruction, operands.get(2)?, operands.get(3))?;
    let second_addr = binary(
        SemanticOperationBinary::Add,
        base_addr.clone(),
        const_u64(4, 64),
        64,
    );

    let mut effects = vec![
        SemanticEffect::Set {
            dst: first_dst.clone(),
            expression: sign_extend_load(base_addr, 32, first_dst.bits()),
        },
        SemanticEffect::Set {
            dst: second_dst.clone(),
            expression: sign_extend_load(second_addr, 32, second_dst.bits()),
        },
    ];

    if let Some(writeback) = writeback_effect(instruction, operands.get(2)?, operands.get(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

#[derive(Clone, Copy)]
pub(super) enum LoadKind {
    FullWidth,
    ZeroExtend(u16),
}

pub(super) fn build_effect_intrinsic(
    _instruction: &Insn,
    operands: &[ArchOperand],
    outputs: Vec<SemanticLocation>,
    name: String,
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(operand_expression)
        .collect::<Vec<_>>();
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name,
            args,
            outputs,
        }],
    ))
}

pub(super) fn build_plain_load_base_immediate(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: dst.bits(),
            },
        }],
    ))
}

pub(super) fn build_zero_extend_load(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    load_bits: u16,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: zero_extend_load(addr, load_bits, dst.bits()),
    }];
    if let Some(writeback) = writeback_effect(instruction, operands.get(1)?, operands.get(2)) {
        effects.push(writeback);
    }
    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_zero_extend_load_base_immediate(
    machine: Architecture,
    operands: &[ArchOperand],
    load_bits: u16,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: zero_extend_load(addr, load_bits, dst.bits()),
        }],
    ))
}

pub(super) fn build_sign_extend_load_base_immediate(
    machine: Architecture,
    operands: &[ArchOperand],
    load_bits: u16,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: sign_extend_load(addr, load_bits, dst.bits()),
        }],
    ))
}

pub(super) fn build_exclusive_load(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    kind: LoadKind,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
    let expression = match kind {
        LoadKind::FullWidth => SemanticExpression::Load {
            space: SemanticAddressSpace::Default,
            addr: Box::new(addr.clone()),
            bits: dst.bits(),
        },
        LoadKind::ZeroExtend(load_bits) => zero_extend_load(addr.clone(), load_bits, dst.bits()),
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set { dst, expression },
            SemanticEffect::Intrinsic {
                name: format!(
                    "arm64.{}.monitor",
                    instruction.mnemonic().unwrap_or("exclusive_load")
                ),
                args: vec![addr],
                outputs: Vec::new(),
            },
        ],
    ))
}

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

pub(super) fn build_move(
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

pub(super) fn build_movk(
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

pub(super) fn build_movz(
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

pub(super) fn build_movn(
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

pub(super) fn build_adc(
    machine: Architecture,
    operands: &[ArchOperand],
    update_flags: bool,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let carry = zero_extend_to_bits(flag_expr("c"), bits);
    let right_with_carry = binary(SemanticOperationBinary::Add, right, carry, bits);
    let expression = binary(
        SemanticOperationBinary::Add,
        left.clone(),
        right_with_carry.clone(),
        bits,
    );
    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: expression.clone(),
    }];
    if update_flags {
        effects.extend(arithmetic_flag_effects(
            SemanticOperationBinary::Add,
            left,
            right_with_carry,
            expression,
        ));
    }
    let _ = machine;
    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_sbc(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let borrow = binary(
        SemanticOperationBinary::Sub,
        const_u64(1, bits),
        zero_extend_to_bits(flag_expr("c"), bits),
        bits,
    );
    let expression = binary(
        SemanticOperationBinary::Sub,
        binary(SemanticOperationBinary::Sub, left, right, bits),
        borrow,
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn build_clz(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::CountLeadingZeros,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_eon(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Xor,
                left,
                binary(
                    SemanticOperationBinary::Xor,
                    right,
                    const_u64(bitmask(bits), bits),
                    bits,
                ),
                bits,
            ),
        }],
    ))
}

pub(super) fn build_binary_assign(
    machine: Architecture,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
    update_flags: bool,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = dst.bits();
    let result = binary(op, left.clone(), right.clone(), bits);

    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: result.clone(),
    }];

    if update_flags {
        effects.extend(arithmetic_flag_effects(op, left, right, result));
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_compare_flags(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let result = binary(
        SemanticOperationBinary::Sub,
        left.clone(),
        right.clone(),
        left.bits(),
    );
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        arithmetic_flag_effects(SemanticOperationBinary::Sub, left, right, result),
    ))
}

pub(super) fn build_compare_add_flags(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let result = binary(
        SemanticOperationBinary::Add,
        left.clone(),
        right.clone(),
        left.bits(),
    );
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        arithmetic_flag_effects(SemanticOperationBinary::Add, left, right, result),
    ))
}

pub(super) fn build_shift_assign(
    machine: Architecture,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let amount = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(op, src, amount, bits),
        }],
    ))
}

pub(super) fn build_conditional_select(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let when_false = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

pub(super) fn build_cset(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(1)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(const_u64(1, bits)),
                when_false: Box::new(const_u64(0, bits)),
                bits,
            },
        }],
    ))
}

pub(super) fn build_csetm(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(1)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(const_u64(bitmask(bits), bits)),
                when_false: Box::new(const_u64(0, bits)),
                bits,
            },
        }],
    ))
}

pub(super) fn build_conditional_select_increment(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let base_false = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let when_false = binary(
        SemanticOperationBinary::Add,
        base_false,
        const_u64(1, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

pub(super) fn build_conditional_increment(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let base = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(2)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let incremented = binary(
        SemanticOperationBinary::Add,
        base.clone(),
        const_u64(1, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(incremented),
                when_false: Box::new(base),
                bits,
            },
        }],
    ))
}

pub(super) fn build_conditional_invert(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let base = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(2)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let inverted = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(base.clone()),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(inverted),
                when_false: Box::new(base),
                bits,
            },
        }],
    ))
}

pub(super) fn build_conditional_select_invert(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let false_src = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let when_false = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(false_src),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

pub(super) fn build_conditional_negate(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(2)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let negated = binary(
        SemanticOperationBinary::Sub,
        const_u64(0, bits),
        src.clone(),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(negated),
                when_false: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_abs(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let zero = const_u64(0, bits);
    let negative = binary(
        SemanticOperationBinary::Sub,
        zero.clone(),
        src.clone(),
        bits,
    );
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(sign_bit(src.clone())),
                when_true: Box::new(negative),
                when_false: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_conditional_select_negate(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let false_src = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let when_false = binary(
        SemanticOperationBinary::Sub,
        const_u64(0, bits),
        false_src,
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

pub(super) fn build_sign_extend_word(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 32)),
                bits,
            },
        }],
    ))
}

pub(super) fn build_sign_extend_byte(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 8)),
                bits,
            },
        }],
    ))
}

pub(super) fn build_sign_extend_halfword(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 16)),
                bits,
            },
        }],
    ))
}

pub(super) fn build_madd(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let addend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Add, product, addend, bits),
        }],
    ))
}

pub(super) fn build_smaddl(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = sign_extend_to_bits(operand_expression(operands.get(1)?)?, 64);
    let right = sign_extend_to_bits(operand_expression(operands.get(2)?)?, 64);
    let addend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Add, product, addend, bits),
        }],
    ))
}

pub(super) fn build_umaddl(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = zero_extend_to_bits(operand_expression(operands.get(1)?)?, 64);
    let right = zero_extend_to_bits(operand_expression(operands.get(2)?)?, 64);
    let addend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Add, product, addend, bits),
        }],
    ))
}

pub(super) fn build_mul(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Mul, left, right, bits),
        }],
    ))
}

pub(super) fn build_mneg(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Sub,
                const_u64(0, bits),
                product,
                bits,
            ),
        }],
    ))
}

pub(super) fn build_umulh(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::UMulHigh, left, right, bits),
        }],
    ))
}

pub(super) fn build_smulh(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::SMulHigh, left, right, bits),
        }],
    ))
}

pub(super) fn build_sdiv(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::SDiv, left, right, bits),
        }],
    ))
}

pub(super) fn build_udiv(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::UDiv, left, right, bits),
        }],
    ))
}

pub(super) fn build_msub(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let subtrahend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, subtrahend, product, bits),
        }],
    ))
}

pub(super) fn build_smsubl(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = sign_extend_to_bits(operand_expression(operands.get(1)?)?, 64);
    let right = sign_extend_to_bits(operand_expression(operands.get(2)?)?, 64);
    let subtrahend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, subtrahend, product, bits),
        }],
    ))
}

pub(super) fn build_umull(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = zero_extend_to_bits(operand_expression(operands.get(1)?)?, 64);
    let right = zero_extend_to_bits(operand_expression(operands.get(2)?)?, 64);
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Mul, left, right, bits),
        }],
    ))
}

pub(super) fn build_umsubl(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = zero_extend_to_bits(operand_expression(operands.get(1)?)?, 64);
    let right = zero_extend_to_bits(operand_expression(operands.get(2)?)?, 64);
    let subtrahend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, subtrahend, product, bits),
        }],
    ))
}

pub(super) fn build_smull(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = sign_extend_to_bits(operand_expression(operands.get(1)?)?, 64);
    let right = sign_extend_to_bits(operand_expression(operands.get(2)?)?, 64);
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Mul, left, right, bits),
        }],
    ))
}

pub(super) fn build_umnegl(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = zero_extend_to_bits(operand_expression(operands.get(1)?)?, 64);
    let right = zero_extend_to_bits(operand_expression(operands.get(2)?)?, 64);
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Sub,
                const_u64(0, bits),
                product,
                bits,
            ),
        }],
    ))
}

pub(super) fn build_unsigned_bitfield_extract(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::ZeroExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src),
                    lsb,
                    bits: width,
                }),
                bits,
            },
        }],
    ))
}

pub(super) fn build_signed_bitfield_extract(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src),
                    lsb,
                    bits: width,
                }),
                bits,
            },
        }],
    ))
}

pub(super) fn build_unsigned_bitfield_insert(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    let extracted = SemanticExpression::Extract {
        arg: Box::new(src),
        lsb: 0,
        bits: width,
    };
    let extended = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(extracted),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Shl,
                extended,
                const_u64(lsb as u64, bits),
                bits,
            ),
        }],
    ))
}

pub(super) fn build_bitfield_insert(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    let field_mask = if width == 0 || lsb >= bits {
        0
    } else {
        ((((1u128 << width.min(64)) - 1) as u64) << lsb) & bitmask(bits)
    };
    let cleared = binary(
        SemanticOperationBinary::And,
        current,
        const_u64((!field_mask) & bitmask(bits), bits),
        bits,
    );
    let inserted = binary(
        SemanticOperationBinary::Shl,
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src),
                lsb: 0,
                bits: width,
            }),
            bits,
        },
        const_u64(lsb as u64, bits),
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

pub(super) fn build_bitfield_insert_low(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    let mask = if width == 0 {
        0
    } else {
        ((1u128 << width.min(64)) - 1) as u64
    };
    let cleared = binary(
        SemanticOperationBinary::And,
        current,
        const_u64((!mask) & bitmask(bits), bits),
        bits,
    );
    let shifted_src = binary(
        SemanticOperationBinary::LShr,
        src,
        const_u64(lsb as u64, bits),
        bits,
    );
    let extracted = SemanticExpression::Extract {
        arg: Box::new(shifted_src),
        lsb: 0,
        bits: width,
    };
    let inserted = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(extracted),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, cleared, inserted, bits),
        }],
    ))
}

pub(super) fn build_signed_bitfield_insert(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    let extracted = SemanticExpression::Extract {
        arg: Box::new(src),
        lsb: 0,
        bits: width,
    };
    let extended = SemanticExpression::Cast {
        op: SemanticOperationCast::SignExtend,
        arg: Box::new(extracted),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Shl,
                extended,
                const_u64(lsb as u64, bits),
                bits,
            ),
        }],
    ))
}

pub(super) fn build_conditional_compare(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let fallback_nzcv = operand_immediate(operands.get(2)?)?;
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let result = binary(op, left.clone(), right.clone(), left.bits());
    let compare_flags = arithmetic_flag_values(op, left, right, result);
    let fallback_flags = [
        ((fallback_nzcv >> 3) & 1) != 0,
        ((fallback_nzcv >> 2) & 1) != 0,
        ((fallback_nzcv >> 1) & 1) != 0,
        (fallback_nzcv & 1) != 0,
    ];
    let flag_names = ["n", "z", "c", "v"];
    let effects = flag_names
        .into_iter()
        .zip(compare_flags)
        .zip(fallback_flags)
        .map(
            |((name, compare_value), fallback_value)| SemanticEffect::Set {
                dst: flag(name),
                expression: SemanticExpression::Select {
                    condition: Box::new(condition.clone()),
                    when_true: Box::new(compare_value),
                    when_false: Box::new(bool_const(fallback_value)),
                    bits: 1,
                },
            },
        )
        .collect();
    let _ = machine;
    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_fcmp_intrinsic(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = match operands.get(1) {
        Some(ArchOperand::Arm64Operand(op)) => match op.op_type {
            Arm64OperandType::Fp(fp) => SemanticExpression::Const {
                value: fp.to_bits() as u128,
                bits: left.bits(),
            },
            _ => operand_expression(operands.get(1)?)?,
        },
        Some(_) => operand_expression(operands.get(1)?)?,
        None => SemanticExpression::Const {
            value: 0,
            bits: left.bits(),
        },
    };
    let compare_flags = fp_compare_flag_values(left, right);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            set_flag("n", compare_flags[0].clone()),
            set_flag("z", compare_flags[1].clone()),
            set_flag("c", compare_flags[2].clone()),
            set_flag("v", compare_flags[3].clone()),
        ],
    ))
}

pub(super) fn build_fccmp(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let fallback_nzcv = operand_immediate(operands.get(2)?)?;
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let compare_flags = fp_compare_flag_values(left, right);
    let fallback_flags = [
        ((fallback_nzcv >> 3) & 1) != 0,
        ((fallback_nzcv >> 2) & 1) != 0,
        ((fallback_nzcv >> 1) & 1) != 0,
        (fallback_nzcv & 1) != 0,
    ];
    let flag_names = ["n", "z", "c", "v"];
    let effects = flag_names
        .into_iter()
        .zip(compare_flags)
        .zip(fallback_flags)
        .map(
            |((name, compare_value), fallback_value)| SemanticEffect::Set {
                dst: flag(name),
                expression: SemanticExpression::Select {
                    condition: Box::new(condition.clone()),
                    when_true: Box::new(compare_value),
                    when_false: Box::new(bool_const(fallback_value)),
                    bits: 1,
                },
            },
        )
        .collect();
    let _ = machine;
    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_bics(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };
    let result = binary(SemanticOperationBinary::And, left, not_right, bits);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            set_flag("n", sign_bit(result.clone())),
            set_flag(
                "z",
                compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
            ),
            set_flag("c", bool_const(false)),
            set_flag("v", bool_const(false)),
        ],
    ))
}

pub(super) fn build_bic(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::And, left, not_right, bits),
        }],
    ))
}

pub(super) fn build_orn(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, left, not_right, bits),
        }],
    ))
}

pub(super) fn build_fp_binary(
    machine: Architecture,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
                bits,
            },
        }],
    ))
}

pub(super) fn build_fp_minmax(
    machine: Architecture,
    operands: &[ArchOperand],
    compare_op: SemanticOperationCompare,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(SemanticExpression::Compare {
                    op: compare_op,
                    left: Box::new(left.clone()),
                    right: Box::new(right.clone()),
                    bits: 1,
                }),
                when_true: Box::new(left),
                when_false: Box::new(right),
                bits,
            },
        }],
    ))
}

pub(super) fn build_fnmul(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let zero = match bits {
        32 => const_u64(f32::to_bits(0.0) as u64, 32),
        64 => const_u64(f64::to_bits(0.0), 64),
        _ => return None,
    };
    let product = SemanticExpression::Binary {
        op: SemanticOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: SemanticOperationBinary::FSub,
                left: Box::new(zero),
                right: Box::new(product),
                bits,
            },
        }],
    ))
}

pub(super) fn build_fmadd(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let addend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = SemanticExpression::Binary {
        op: SemanticOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: SemanticOperationBinary::FAdd,
                left: Box::new(product),
                right: Box::new(addend),
                bits,
            },
        }],
    ))
}

pub(super) fn build_fmsub(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let addend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = SemanticExpression::Binary {
        op: SemanticOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: SemanticOperationBinary::FSub,
                left: Box::new(addend),
                right: Box::new(product),
                bits,
            },
        }],
    ))
}

pub(super) fn build_scvtf(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::IntToFloat,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_ucvtf(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::UIntToFloat,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_fcvtzs(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::FloatToInt,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_fcvtzu(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::FloatToUInt,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_intrinsic_fallthrough(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    outputs: Option<Vec<SemanticLocation>>,
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(operand_expression)
        .collect::<Vec<_>>();
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", instruction.mnemonic().unwrap_or("intrinsic")),
            args,
            outputs: outputs.unwrap_or_default(),
        }],
    ))
}

pub(super) fn build_movi(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let Some(imm) = operands.get(1).and_then(operand_immediate) else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (lane_count, lane_bits) = if op_str.contains(".16b") {
        (16usize, 8usize)
    } else if op_str.contains(".8b") {
        (8usize, 8usize)
    } else if op_str.contains(".2d") {
        (2usize, 64usize)
    } else if op_str.contains(".2s") {
        (2usize, 32usize)
    } else if op_str.starts_with('d') {
        (1usize, 64usize)
    } else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let lane_mask = if lane_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << lane_bits) - 1
    };
    let lane_value = imm as u128 & lane_mask;
    let mut value = 0u128;
    for lane in 0..lane_count {
        value |= lane_value << (lane * lane_bits);
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Const { value, bits },
        }],
    ))
}

pub(super) fn build_fmov(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let Some(dst) = operands
        .first()
        .and_then(|operand| operand_location(machine, operand))
    else {
        return build_intrinsic_fallthrough(machine, instruction, operands, None);
    };
    let bits = location_bits(&dst);
    let src = match operands.get(1) {
        Some(ArchOperand::Arm64Operand(op)) => match op.op_type {
            Arm64OperandType::Fp(fp) => SemanticExpression::Const {
                value: if bits == 32 {
                    (fp as f32).to_bits() as u128
                } else {
                    fp.to_bits() as u128
                },
                bits,
            },
            _ => operand_expression(operands.get(1)?)?,
        },
        _ => {
            return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
        }
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: src,
        }],
    ))
}

pub(super) fn parse_vector_arrangement(op_str: &str) -> Option<(u16, u16)> {
    if op_str.contains(".16b") {
        Some((16, 8))
    } else if op_str.contains(".8b") {
        Some((8, 8))
    } else if op_str.contains(".8h") {
        Some((8, 16))
    } else if op_str.contains(".4h") {
        Some((4, 16))
    } else if op_str.contains(".4s") {
        Some((4, 32))
    } else if op_str.contains(".2s") {
        Some((2, 32))
    } else if op_str.contains(".2d") {
        Some((2, 64))
    } else {
        None
    }
}

pub(super) fn zero_extend_if_needed(
    expression: SemanticExpression,
    src_bits: u16,
    dst_bits: u16,
) -> SemanticExpression {
    if src_bits == dst_bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits: dst_bits,
        }
    }
}

pub(super) fn build_vector_compare(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    compare: SemanticOperationCompare,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    let ones = bitmask(lane_bits) as u128;
    let parts = (0..lane_count)
        .rev()
        .map(|lane| {
            let left_lane = SemanticExpression::Extract {
                arg: Box::new(left.clone()),
                lsb: lane * lane_bits,
                bits: lane_bits,
            };
            let right_lane = SemanticExpression::Extract {
                arg: Box::new(right.clone()),
                lsb: lane * lane_bits,
                bits: lane_bits,
            };
            SemanticExpression::Select {
                condition: Box::new(SemanticExpression::Compare {
                    op: compare,
                    left: Box::new(left_lane),
                    right: Box::new(right_lane),
                    bits: 1,
                }),
                when_true: Box::new(SemanticExpression::Const {
                    value: ones,
                    bits: lane_bits,
                }),
                when_false: Box::new(SemanticExpression::Const {
                    value: 0,
                    bits: lane_bits,
                }),
                bits: lane_bits,
            }
        })
        .collect::<Vec<_>>();
    let arrangement_bits = lane_count * lane_bits;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn build_uzp1(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    let mut lanes_low_to_high = Vec::new();
    let half = lane_count / 2;
    for lane in 0..half {
        lanes_low_to_high.push((true, lane * 2));
    }
    for lane in 0..half {
        lanes_low_to_high.push((false, lane * 2));
    }
    let parts = lanes_low_to_high
        .into_iter()
        .rev()
        .map(|(from_left, lane)| SemanticExpression::Extract {
            arg: Box::new(if from_left {
                left.clone()
            } else {
                right.clone()
            }),
            lsb: lane * lane_bits,
            bits: lane_bits,
        })
        .collect::<Vec<_>>();
    let arrangement_bits = lane_count * lane_bits;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_vector_add_reduce(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(operands.get(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    let mut sum = SemanticExpression::Const {
        value: 0,
        bits: dst_bits,
    };
    for lane in 0..lane_count {
        let lane_expr = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: lane * lane_bits,
                bits: lane_bits,
            }),
            bits: dst_bits,
        };
        sum = binary(SemanticOperationBinary::Add, sum, lane_expr, dst_bits);
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: sum,
        }],
    ))
}

pub(super) fn build_addv(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    build_vector_add_reduce(machine, instruction, operands)
}

pub(super) fn build_uaddlv(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    build_vector_add_reduce(machine, instruction, operands)
}

fn lane_bits_from_vas(vas: Arm64Vas) -> Option<u16> {
    match vas {
        Arm64Vas::ARM64_VAS_16B
        | Arm64Vas::ARM64_VAS_8B
        | Arm64Vas::ARM64_VAS_4B
        | Arm64Vas::ARM64_VAS_1B => Some(8),
        Arm64Vas::ARM64_VAS_8H
        | Arm64Vas::ARM64_VAS_4H
        | Arm64Vas::ARM64_VAS_2H
        | Arm64Vas::ARM64_VAS_1H => Some(16),
        Arm64Vas::ARM64_VAS_4S | Arm64Vas::ARM64_VAS_2S | Arm64Vas::ARM64_VAS_1S => Some(32),
        Arm64Vas::ARM64_VAS_2D | Arm64Vas::ARM64_VAS_1D => Some(64),
        Arm64Vas::ARM64_VAS_1Q => Some(128),
        _ => None,
    }
}

pub(super) fn build_ld1_lane(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let addr = memory_address(operands.get(1)?)?;
    let ArchOperand::Arm64Operand(op) = operands.first()? else {
        return None;
    };
    let lane_index = op.vector_index? as u16;
    let lane_bits = lane_bits_from_vas(op.vas)?;
    let lane_count = dst_bits / lane_bits;
    let load = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(addr),
        bits: lane_bits,
    };
    let parts = (0..lane_count)
        .rev()
        .map(|lane| {
            if lane == lane_index {
                load.clone()
            } else {
                SemanticExpression::Extract {
                    arg: Box::new(current.clone()),
                    lsb: lane * lane_bits,
                    bits: lane_bits,
                }
            }
        })
        .collect::<Vec<_>>();
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts,
                bits: dst_bits,
            },
        }],
    ))
}

pub(super) fn build_dup(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(operands.get(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    let lane = SemanticExpression::Extract {
        arg: Box::new(src),
        lsb: 0,
        bits: lane_bits,
    };
    let parts = (0..lane_count).map(|_| lane.clone()).collect::<Vec<_>>();
    let arrangement_bits = lane_count * lane_bits;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn build_addp(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (src_lanes, lane_bits, dst_lanes) = if op_str.contains(".16b") {
        (16u16, 8u16, 16u16)
    } else if op_str.contains(".8h") {
        (8u16, 16u16, 8u16)
    } else if op_str.contains(".4s") {
        (4u16, 32u16, 4u16)
    } else if op_str.contains(".2d") {
        (2u16, 64u16, 2u16)
    } else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    if dst_lanes != src_lanes {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    }
    let mut parts = Vec::new();
    for lane in (0..(src_lanes / 2)).rev() {
        let r0 = SemanticExpression::Extract {
            arg: Box::new(right.clone()),
            lsb: lane * 2 * lane_bits,
            bits: lane_bits,
        };
        let r1 = SemanticExpression::Extract {
            arg: Box::new(right.clone()),
            lsb: (lane * 2 + 1) * lane_bits,
            bits: lane_bits,
        };
        parts.push(binary(SemanticOperationBinary::Add, r0, r1, lane_bits));
    }
    for lane in (0..(src_lanes / 2)).rev() {
        let l0 = SemanticExpression::Extract {
            arg: Box::new(left.clone()),
            lsb: lane * 2 * lane_bits,
            bits: lane_bits,
        };
        let l1 = SemanticExpression::Extract {
            arg: Box::new(left.clone()),
            lsb: (lane * 2 + 1) * lane_bits,
            bits: lane_bits,
        };
        parts.push(binary(SemanticOperationBinary::Add, l0, l1, lane_bits));
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: SemanticExpression::Concat {
                parts,
                bits: dst.bits(),
            },
        }],
    ))
}

pub(super) fn build_addhn(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (lane_count, src_lane_bits, dst_lane_bits) =
        if op_str.contains(".8b") && op_str.contains(".8h") {
            (8u16, 16u16, 8u16)
        } else if op_str.contains(".4h") && op_str.contains(".4s") {
            (4u16, 32u16, 16u16)
        } else if op_str.contains(".2s") && op_str.contains(".2d") {
            (2u16, 64u16, 32u16)
        } else {
            return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
        };
    let mut parts = Vec::new();
    for lane in (0..lane_count).rev() {
        let sum = binary(
            SemanticOperationBinary::Add,
            SemanticExpression::Extract {
                arg: Box::new(left.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            },
            SemanticExpression::Extract {
                arg: Box::new(right.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            },
            src_lane_bits,
        );
        parts.push(SemanticExpression::Extract {
            arg: Box::new(sum),
            lsb: dst_lane_bits,
            bits: dst_lane_bits,
        });
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: SemanticExpression::Concat {
                parts,
                bits: dst.bits(),
            },
        }],
    ))
}

pub(super) fn build_addhn2(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let current_dst = operand_expression(operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (lane_count, src_lane_bits, dst_lane_bits, low_half_bits) =
        if op_str.contains(".16b") && op_str.contains(".8h") {
            (8u16, 16u16, 8u16, 64u16)
        } else if op_str.contains(".8h") && op_str.contains(".4s") {
            (4u16, 32u16, 16u16, 64u16)
        } else if op_str.contains(".4s") && op_str.contains(".2d") {
            (2u16, 64u16, 32u16, 64u16)
        } else {
            return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
        };
    let mut upper_parts = Vec::new();
    for lane in (0..lane_count).rev() {
        let sum = binary(
            SemanticOperationBinary::Add,
            SemanticExpression::Extract {
                arg: Box::new(left.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            },
            SemanticExpression::Extract {
                arg: Box::new(right.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            },
            src_lane_bits,
        );
        upper_parts.push(SemanticExpression::Extract {
            arg: Box::new(sum),
            lsb: dst_lane_bits,
            bits: dst_lane_bits,
        });
    }
    let upper = SemanticExpression::Concat {
        parts: upper_parts,
        bits: low_half_bits,
    };
    let lower = SemanticExpression::Extract {
        arg: Box::new(current_dst),
        lsb: 0,
        bits: low_half_bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: vec![upper, lower],
                bits: 128,
            },
        }],
    ))
}

pub(super) fn build_rev64(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(operands.get(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    let lanes_per_chunk = (64 / lane_bits).max(1);
    let mut output_lanes_low_to_high = Vec::new();
    let mut chunk_start = 0u16;
    while chunk_start < lane_count {
        for lane in 0..lanes_per_chunk {
            output_lanes_low_to_high.push(chunk_start + (lanes_per_chunk - 1 - lane));
        }
        chunk_start += lanes_per_chunk;
    }
    let parts = output_lanes_low_to_high
        .into_iter()
        .rev()
        .map(|lane| SemanticExpression::Extract {
            arg: Box::new(src.clone()),
            lsb: lane * lane_bits,
            bits: lane_bits,
        })
        .collect::<Vec<_>>();
    let arrangement_bits = lane_count * lane_bits;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn build_cnt(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(operands.get(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    if lane_bits != 8 {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    }
    let parts = (0..lane_count)
        .rev()
        .map(|lane| SemanticExpression::Unary {
            op: SemanticOperationUnary::PopCount,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: lane * 8,
                bits: 8,
            }),
            bits: 8,
        })
        .collect::<Vec<_>>();
    let arrangement_bits = lane_count * 8;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn build_extr(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let shift = operand_immediate(operands.get(3)?)? as u16;
    let concat = SemanticExpression::Concat {
        parts: vec![left, right],
        bits: bits * 2,
    };
    let shifted = binary(
        SemanticOperationBinary::LShr,
        concat,
        const_u64(shift as u64, bits * 2),
        bits * 2,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Extract {
                arg: Box::new(shifted),
                lsb: 0,
                bits,
            },
        }],
    ))
}

pub(super) fn build_sshll(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let shift = operands.get(2).and_then(operand_immediate).unwrap_or(0);
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (lane_count, src_lane_bits, dst_lane_bits) =
        if op_str.contains(".8h") && op_str.contains(".8b") {
            (8u16, 8u16, 16u16)
        } else if op_str.contains(".4s") && op_str.contains(".4h") {
            (4u16, 16u16, 32u16)
        } else if op_str.contains(".2d") && op_str.contains(".2s") {
            (2u16, 32u16, 64u16)
        } else {
            return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
        };
    if shift != 0 {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    }
    let mut parts = Vec::new();
    for lane in (0..lane_count).rev() {
        parts.push(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            }),
            bits: dst_lane_bits,
        });
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits: 128 },
        }],
    ))
}

pub(super) fn build_fabs(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::Abs,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_fneg(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::Neg,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_mvn(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::Not,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_neg(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, const_u64(0, bits), src, bits),
        }],
    ))
}

pub(super) fn build_rbit(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::BitReverse,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_rev(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::ByteSwap,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(super) fn build_rev16(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let expression = reverse_bytes_in_chunks(src, bits, 16)?;
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn build_rev32(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let expression = reverse_bytes_in_chunks(src, bits, 32)?;
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn build_zero_extend_byte(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: zero_extend_to_bits(truncate_to_bits(src, 8), bits),
        }],
    ))
}

pub(super) fn build_zero_extend_halfword(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: zero_extend_to_bits(truncate_to_bits(src, 16), bits),
        }],
    ))
}

pub(super) fn build_ldr(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = match operands.get(1) {
        Some(operand) if memory_address(operand).is_some() => {
            effective_memory_address(instruction, operand, operands.get(2))?
        }
        Some(operand) => operand_expression(operand)?,
        None => return None,
    };

    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: SemanticExpression::Load {
            space: SemanticAddressSpace::Default,
            addr: Box::new(addr),
            bits: dst.bits(),
        },
    }];

    if let Some(mem_operand) = operands.get(1) {
        if memory_address(mem_operand).is_some() {
            if let Some(writeback) = writeback_effect(instruction, mem_operand, operands.get(2)) {
                effects.push(writeback);
            }
        }
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_test_flags(
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let bits = left.bits();
    let result = binary(SemanticOperationBinary::And, left, right, bits);
    let _ = instruction;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            set_flag("n", sign_bit(result.clone())),
            set_flag(
                "z",
                compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
            ),
            set_flag("c", bool_const(false)),
            set_flag("v", bool_const(false)),
        ],
    ))
}

pub(super) fn arithmetic_flag_effects(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
) -> Vec<SemanticEffect> {
    let bits = result.bits();
    let sign_left = sign_bit(left.clone());
    let sign_right = sign_bit(right.clone());
    let sign_result = sign_bit(result.clone());

    let carry = match op {
        SemanticOperationBinary::Add => {
            compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
        }
        SemanticOperationBinary::Sub => {
            compare(SemanticOperationCompare::Uge, left.clone(), right.clone())
        }
        _ => bool_const(false),
    };

    let overflow = match op {
        SemanticOperationBinary::Add => binary(
            SemanticOperationBinary::And,
            unary_not(binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            )),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        SemanticOperationBinary::Sub => binary(
            SemanticOperationBinary::And,
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            ),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        _ => bool_const(false),
    };

    vec![
        set_flag("n", sign_result),
        set_flag(
            "z",
            compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
        ),
        set_flag("c", carry),
        set_flag("v", overflow),
    ]
}

pub(super) fn arithmetic_flag_values(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
) -> [SemanticExpression; 4] {
    let bits = result.bits();
    let sign_left = sign_bit(left.clone());
    let sign_right = sign_bit(right.clone());
    let sign_result = sign_bit(result.clone());

    let carry = match op {
        SemanticOperationBinary::Add => {
            compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
        }
        SemanticOperationBinary::Sub => {
            compare(SemanticOperationCompare::Uge, left.clone(), right.clone())
        }
        _ => bool_const(false),
    };

    let overflow = match op {
        SemanticOperationBinary::Add => binary(
            SemanticOperationBinary::And,
            unary_not(binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            )),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        SemanticOperationBinary::Sub => binary(
            SemanticOperationBinary::And,
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            ),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        _ => bool_const(false),
    };

    [
        sign_result,
        compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
        carry,
        overflow,
    ]
}

pub(super) fn fp_compare_flag_values(
    left: SemanticExpression,
    right: SemanticExpression,
) -> [SemanticExpression; 4] {
    let unordered = compare(
        SemanticOperationCompare::Unordered,
        left.clone(),
        right.clone(),
    );
    [
        compare(SemanticOperationCompare::Olt, left.clone(), right.clone()),
        compare(SemanticOperationCompare::Oeq, left.clone(), right.clone()),
        binary(
            SemanticOperationBinary::Or,
            compare(SemanticOperationCompare::Oge, left.clone(), right.clone()),
            unordered.clone(),
            1,
        ),
        unordered,
    ]
}

pub(super) fn condition_from_suffix(suffix: &str) -> Option<SemanticExpression> {
    let z = flag_expr("z");
    let n = flag_expr("n");
    let c = flag_expr("c");
    let v = flag_expr("v");

    Some(match suffix {
        "eq" => z,
        "ne" => unary_not(z),
        "hs" | "cs" => c,
        "lo" | "cc" => unary_not(c),
        "mi" => n,
        "pl" => unary_not(n),
        "vs" => v,
        "vc" => unary_not(v),
        "hi" => binary(
            SemanticOperationBinary::And,
            c,
            unary_not(flag_expr("z")),
            1,
        ),
        "ls" => binary(SemanticOperationBinary::Or, unary_not(c), flag_expr("z"), 1),
        "ge" => compare(SemanticOperationCompare::Eq, n, v),
        "lt" => compare(SemanticOperationCompare::Ne, n, v),
        "gt" => binary(
            SemanticOperationBinary::And,
            unary_not(flag_expr("z")),
            compare(SemanticOperationCompare::Eq, flag_expr("n"), flag_expr("v")),
            1,
        ),
        "le" => binary(
            SemanticOperationBinary::Or,
            flag_expr("z"),
            compare(SemanticOperationCompare::Ne, flag_expr("n"), flag_expr("v")),
            1,
        ),
        "al" | "nv" => bool_const(true),
        _ => return None,
    })
}

pub(super) fn condition_from_cc(cc: u64) -> Option<SemanticExpression> {
    let suffix = match cc {
        1 => "eq",
        2 => "ne",
        3 => "hs",
        4 => "lo",
        5 => "mi",
        6 => "pl",
        7 => "vs",
        8 => "vc",
        9 => "hi",
        10 => "ls",
        11 => "ge",
        12 => "lt",
        13 => "gt",
        14 => "le",
        15 | 16 => "al",
        _ => return None,
    };
    condition_from_suffix(suffix)
}

pub(super) fn operand_expression(operand: &ArchOperand) -> Option<SemanticExpression> {
    match operand {
        ArchOperand::Arm64Operand(op) => match op.op_type {
            Arm64OperandType::Reg(reg) => Some(reg_expr(reg, register_bits(reg))),
            Arm64OperandType::Imm(imm) => Some(const_u64(imm as u64, 64)),
            Arm64OperandType::Mem(_) => Some(SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(memory_address(operand)?),
                bits: 64,
            }),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn operand_location(
    machine: Architecture,
    operand: &ArchOperand,
) -> Option<SemanticLocation> {
    match operand {
        ArchOperand::Arm64Operand(op) => match op.op_type {
            Arm64OperandType::Reg(reg_id) => Some(reg_location(reg_id, register_bits(reg_id))),
            Arm64OperandType::Mem(_) => Some(SemanticLocation::Memory {
                space: SemanticAddressSpace::Default,
                addr: Box::new(memory_address(operand)?),
                bits: pointer_bits(machine),
            }),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn operand_immediate(operand: &ArchOperand) -> Option<u64> {
    match operand {
        ArchOperand::Arm64Operand(op) => match op.op_type {
            Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => Some(imm as u64),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn memory_address(operand: &ArchOperand) -> Option<SemanticExpression> {
    let ArchOperand::Arm64Operand(op) = operand else {
        return None;
    };
    let Arm64OperandType::Mem(mem) = op.op_type else {
        return None;
    };

    let mut address = if mem.base() != RegId(Arm64Reg::ARM64_REG_INVALID as u16) {
        Some(reg_expr(mem.base(), register_bits(mem.base())))
    } else {
        None
    };

    if mem.index() != RegId(Arm64Reg::ARM64_REG_INVALID as u16) {
        let index = reg_expr(mem.index(), register_bits(mem.index()));
        address = Some(match address {
            Some(base) => binary(SemanticOperationBinary::Add, base, index, 64),
            None => index,
        });
    }

    let address = address.unwrap_or_else(|| const_u64(0, 64));
    if mem.disp() == 0 {
        Some(address)
    } else {
        Some(binary(
            SemanticOperationBinary::Add,
            address,
            const_u64(mem.disp() as i64 as u64, 64),
            64,
        ))
    }
}

pub(super) fn base_register_expression(operand: &ArchOperand) -> Option<SemanticExpression> {
    let ArchOperand::Arm64Operand(op) = operand else {
        return None;
    };
    let Arm64OperandType::Mem(mem) = op.op_type else {
        return None;
    };
    Some(reg_expr(mem.base(), register_bits(mem.base())))
}

pub(super) fn effective_memory_address(
    instruction: &Insn,
    mem_operand: &ArchOperand,
    writeback_operand: Option<&ArchOperand>,
) -> Option<SemanticExpression> {
    if is_post_indexed(instruction, writeback_operand) {
        return base_register_expression(mem_operand);
    }
    memory_address(mem_operand)
}

pub(super) fn effective_base_plus_immediate(
    base_operand: &ArchOperand,
    displacement_operand: Option<&ArchOperand>,
) -> Option<SemanticExpression> {
    let base = operand_expression(base_operand)?;
    let displacement = displacement_operand
        .and_then(operand_immediate)
        .unwrap_or(0);
    if displacement == 0 {
        Some(base)
    } else {
        Some(binary(
            SemanticOperationBinary::Add,
            base,
            const_u64(displacement, 64),
            64,
        ))
    }
}

pub(super) fn base_immediate_load_address(
    base_operand: &ArchOperand,
    displacement_operand: Option<&ArchOperand>,
) -> Option<SemanticExpression> {
    memory_address(base_operand)
        .or_else(|| effective_base_plus_immediate(base_operand, displacement_operand))
}

pub(super) fn writeback_effect(
    instruction: &Insn,
    mem_operand: &ArchOperand,
    writeback_operand: Option<&ArchOperand>,
) -> Option<SemanticEffect> {
    let ArchOperand::Arm64Operand(op) = mem_operand else {
        return None;
    };
    let Arm64OperandType::Mem(mem) = op.op_type else {
        return None;
    };
    if !instruction
        .op_str()
        .is_some_and(|op_str| op_str.contains("],") || op_str.contains("]!"))
        && writeback_operand.and_then(operand_immediate).is_none()
    {
        return None;
    }
    let delta = writeback_operand
        .and_then(operand_immediate)
        .unwrap_or(mem.disp() as i64 as u64);
    if delta == 0 {
        return None;
    }
    let base = reg_location(mem.base(), register_bits(mem.base()));
    Some(SemanticEffect::Set {
        dst: base.clone(),
        expression: binary(
            SemanticOperationBinary::Add,
            SemanticExpression::Read(Box::new(base)),
            const_u64(delta, 64),
            64,
        ),
    })
}

pub(super) fn is_post_indexed(instruction: &Insn, writeback_operand: Option<&ArchOperand>) -> bool {
    writeback_operand.is_some()
        || instruction
            .op_str()
            .is_some_and(|op_str| op_str.contains("],"))
}

pub(super) fn zero_extend_load(
    addr: SemanticExpression,
    load_bits: u16,
    dst_bits: u16,
) -> SemanticExpression {
    let load = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(addr),
        bits: load_bits,
    };
    if load_bits == dst_bits {
        load
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(load),
            bits: dst_bits,
        }
    }
}

pub(super) fn sign_extend_load(
    addr: SemanticExpression,
    load_bits: u16,
    dst_bits: u16,
) -> SemanticExpression {
    let load = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(addr),
        bits: load_bits,
    };
    if load_bits == dst_bits {
        load
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(load),
            bits: dst_bits,
        }
    }
}

pub(super) fn zero_extend_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub(super) fn parse_move_wide_immediate<'a, I>(operands: I, bits: u16) -> Option<(u64, u16)>
where
    I: IntoIterator<Item = &'a ArchOperand>,
{
    let mut immediate = None;
    let mut shift = 0u16;
    for operand in operands {
        let ArchOperand::Arm64Operand(op) = operand else {
            continue;
        };
        match op.op_type {
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
    Some((immediate & bitmask(bits), shift))
}

pub(super) fn reverse_bytes_in_chunks(
    src: SemanticExpression,
    bits: u16,
    chunk_bits: u16,
) -> Option<SemanticExpression> {
    if bits == 0 || chunk_bits == 0 || bits % chunk_bits != 0 || chunk_bits % 8 != 0 {
        return None;
    }
    let bytes_per_chunk = chunk_bits / 8;
    let chunk_count = bits / chunk_bits;
    let mut parts = Vec::with_capacity(bits as usize / 8);
    for chunk in (0..chunk_count).rev() {
        let base_byte = chunk * bytes_per_chunk;
        for byte in 0..bytes_per_chunk {
            parts.push(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: (base_byte + byte) * 8,
                bits: 8,
            });
        }
    }
    Some(SemanticExpression::Concat { parts, bits })
}

pub(super) fn sign_extend_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub(super) fn truncate_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Extract {
            arg: Box::new(expression),
            lsb: 0,
            bits,
        }
    }
}

pub(super) fn pointer_bits(_machine: Architecture) -> u16 {
    64
}

pub(super) fn location_bits(location: &SemanticLocation) -> u16 {
    match location {
        SemanticLocation::Register { bits, .. }
        | SemanticLocation::Flag { bits, .. }
        | SemanticLocation::ProgramCounter { bits }
        | SemanticLocation::Temporary { bits, .. }
        | SemanticLocation::Memory { bits, .. } => *bits,
    }
}

pub(super) fn register_bits(reg: RegId) -> u16 {
    match reg.0 as u32 {
        id if id == Arm64Reg::ARM64_REG_WSP || id == Arm64Reg::ARM64_REG_WZR => 32,
        id if (Arm64Reg::ARM64_REG_W0..=Arm64Reg::ARM64_REG_W30).contains(&id) => 32,
        id if id == Arm64Reg::ARM64_REG_SP
            || id == Arm64Reg::ARM64_REG_FP
            || id == Arm64Reg::ARM64_REG_LR
            || id == Arm64Reg::ARM64_REG_XZR =>
        {
            64
        }
        id if (Arm64Reg::ARM64_REG_X0..=Arm64Reg::ARM64_REG_X28).contains(&id) => 64,
        id if (Arm64Reg::ARM64_REG_B0..=Arm64Reg::ARM64_REG_B31).contains(&id) => 8,
        id if (Arm64Reg::ARM64_REG_H0..=Arm64Reg::ARM64_REG_H31).contains(&id) => 16,
        id if (Arm64Reg::ARM64_REG_S0..=Arm64Reg::ARM64_REG_S31).contains(&id) => 32,
        id if (Arm64Reg::ARM64_REG_D0..=Arm64Reg::ARM64_REG_D31).contains(&id) => 64,
        id if (Arm64Reg::ARM64_REG_Q0..=Arm64Reg::ARM64_REG_Q31).contains(&id) => 128,
        id if (Arm64Reg::ARM64_REG_V0..=Arm64Reg::ARM64_REG_V31).contains(&id) => 128,
        _ => 64,
    }
}

pub(super) fn reg_location(reg: RegId, bits: u16) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("reg_{}", reg.0),
        bits,
    }
}

pub(super) fn reg_expr(reg: RegId, bits: u16) -> SemanticExpression {
    SemanticExpression::Read(Box::new(reg_location(reg, bits)))
}

pub(super) fn flag(name: &str) -> SemanticLocation {
    SemanticLocation::Flag {
        name: name.to_string(),
        bits: 1,
    }
}

pub(super) fn flag_expr(name: &str) -> SemanticExpression {
    SemanticExpression::Read(Box::new(flag(name)))
}

pub(super) fn set_flag(name: &str, expression: SemanticExpression) -> SemanticEffect {
    SemanticEffect::Set {
        dst: flag(name),
        expression,
    }
}

pub(super) fn const_u64(value: u64, bits: u16) -> SemanticExpression {
    let masked = if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    };
    SemanticExpression::Const {
        value: masked as u128,
        bits,
    }
}

pub(super) fn bitmask(bits: u16) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

pub(super) fn bool_const(value: bool) -> SemanticExpression {
    const_u64(value as u64, 1)
}

pub(super) fn binary(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    SemanticExpression::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub(super) fn compare(
    op: SemanticOperationCompare,
    left: SemanticExpression,
    right: SemanticExpression,
) -> SemanticExpression {
    SemanticExpression::Compare {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits: 1,
    }
}

pub(super) fn unary_not(arg: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(arg),
        bits: 1,
    }
}

pub(super) fn sign_bit(arg: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        lsb: arg.bits() - 1,
        arg: Box::new(arg),
        bits: 1,
    }
}

pub(super) fn complete(
    terminator: SemanticTerminator,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics: Vec::new(),
    }
}

pub(super) fn unsupported_fallthrough(
    machine: Architecture,
    instruction: &Insn,
    message: &str,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        abi: None,
        encoding: Some(instruction_encoding(machine, instruction)),
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: SemanticTerminator::FallThrough,
        diagnostics: vec![diagnostic(
            SemanticDiagnosticKind::UnsupportedInstruction,
            format!(
                "0x{:x}: {} ({})",
                instruction.address(),
                message,
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
    }
}

pub(super) fn instruction_encoding(
    machine: Architecture,
    instruction: &Insn,
) -> InstructionEncoding {
    let mnemonic = instruction.mnemonic().unwrap_or("unknown").to_string();
    let disassembly = match instruction.op_str() {
        Some(op_str) if !op_str.is_empty() => format!("{mnemonic} {op_str}"),
        _ => mnemonic.clone(),
    };
    InstructionEncoding {
        architecture: machine.to_string(),
        mnemonic,
        disassembly,
        address: instruction.address(),
        bytes: instruction.bytes().to_vec(),
    }
}

pub(super) fn diagnostic(
    kind: SemanticDiagnosticKind,
    message: impl Into<String>,
) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.into(),
    }
}
