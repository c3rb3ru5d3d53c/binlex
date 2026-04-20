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
    InstructionSemantics, SemanticAddressSpace, SemanticDiagnostic, SemanticDiagnosticKind,
    SemanticEffect, SemanticExpression, SemanticLocation, SemanticOperationBinary,
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticStatus,
    SemanticTerminator,
};
use capstone::Insn;
use capstone::RegId;
use capstone::arch::ArchOperand;
use capstone::arch::arm64::{Arm64OperandType, Arm64Reg, Arm64Shift};

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

    if let Some(writeback) = writeback_effect(operands.get(2)?, operands.get(3)) {
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

    if let Some(writeback) = writeback_effect(operands.get(2)?, operands.get(3)) {
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

    if let Some(writeback) = writeback_effect(operands.get(2)?, operands.get(3)) {
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
    let addr = effective_base_plus_immediate(operands.get(1)?, operands.get(2))?;
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
    if let Some(writeback) = writeback_effect(operands.get(1)?, operands.get(2)) {
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
    let addr = effective_base_plus_immediate(operands.get(1)?, operands.get(2))?;
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
    let addr = effective_base_plus_immediate(operands.get(1)?, operands.get(2))?;
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
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let carry = zero_extend_to_bits(flag_expr("c"), bits);
    let expression = binary(
        SemanticOperationBinary::Add,
        binary(SemanticOperationBinary::Add, left, right, bits),
        carry,
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
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
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(3).and_then(operand_immediate))?)?;
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
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(1).and_then(operand_immediate))?)?;
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
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(1).and_then(operand_immediate))?)?;
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
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(3).and_then(operand_immediate))?)?;
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
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(2).and_then(operand_immediate))?)?;
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

pub(super) fn build_conditional_select_invert(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let false_src = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(3).and_then(operand_immediate))?)?;
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
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(2).and_then(operand_immediate))?)?;
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

pub(super) fn build_conditional_select_negate(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let false_src = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(3).and_then(operand_immediate))?)?;
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
    let lsb = operand_immediate(operands.get(3)?)? as u16;
    let width = operand_immediate(operands.get(4)?)? as u16;
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
    let current = operand_expression(operands.get(1)?)?;
    let src = operand_expression(operands.get(2)?)?;
    let lsb = operand_immediate(operands.get(3)?)? as u16;
    let width = operand_immediate(operands.get(4)?)? as u16;
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
    let current = operand_expression(operands.get(1)?)?;
    let src = operand_expression(operands.get(2)?)?;
    let lsb = operand_immediate(operands.get(3)?)? as u16;
    let width = operand_immediate(operands.get(4)?)? as u16;
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
    let lsb = operand_immediate(operands.get(3)?)? as u16;
    let width = operand_immediate(operands.get(4)?)? as u16;
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
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let fallback_nzcv = operand_immediate(operands.get(2)?)?;
    let condition =
        condition_from_cc(condition_code.or_else(|| operands.get(3).and_then(operand_immediate))?)?;
    let result = binary(
        SemanticOperationBinary::Sub,
        left.clone(),
        right.clone(),
        left.bits(),
    );
    let compare_flags = arithmetic_flag_values(SemanticOperationBinary::Sub, left, right, result);
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
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(operand_expression)
        .collect::<Vec<_>>();
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", instruction.mnemonic().unwrap_or("fcmp")),
            args,
            outputs: vec![flag("n"), flag("z"), flag("c"), flag("v")],
        }],
    ))
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

pub(super) fn build_fp_intrinsic_writeback(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let outputs = vec![operand_location(machine, operands.first()?)?];
    build_intrinsic_fallthrough(machine, instruction, operands, Some(outputs))
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

pub(super) fn build_fmov(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    match (
        operands
            .first()
            .and_then(|operand| operand_location(machine, operand)),
        operands.get(1).and_then(operand_expression),
    ) {
        (Some(dst), Some(src)) => Some(complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Set {
                dst,
                expression: src,
            }],
        )),
        _ => build_intrinsic_fallthrough(
            machine,
            instruction,
            operands,
            Some(vec![operand_location(machine, operands.first()?)?]),
        ),
    }
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
            expression: SemanticExpression::Intrinsic {
                name: String::from("arm64.rbit"),
                args: vec![src],
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
            if let Some(writeback) = writeback_effect(mem_operand, operands.get(2)) {
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
        0 => "eq",
        1 => "ne",
        2 => "hs",
        3 => "lo",
        4 => "mi",
        5 => "pl",
        6 => "vs",
        7 => "vc",
        8 => "hi",
        9 => "ls",
        10 => "ge",
        11 => "lt",
        12 => "gt",
        13 => "le",
        14 | 15 => "al",
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

pub(super) fn writeback_effect(
    mem_operand: &ArchOperand,
    writeback_operand: Option<&ArchOperand>,
) -> Option<SemanticEffect> {
    let ArchOperand::Arm64Operand(op) = mem_operand else {
        return None;
    };
    let Arm64OperandType::Mem(mem) = op.op_type else {
        return None;
    };
    let delta = match writeback_operand.and_then(operand_immediate) {
        Some(immediate) => immediate,
        None => mem.disp() as i64 as u64,
    };
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
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics: Vec::new(),
    }
}

pub(super) fn unsupported_fallthrough(instruction: &Insn, message: &str) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
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

pub(super) fn diagnostic(
    kind: SemanticDiagnosticKind,
    message: impl Into<String>,
) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.into(),
    }
}
