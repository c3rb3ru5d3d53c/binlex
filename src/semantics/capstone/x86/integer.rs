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

extern crate capstone;

use crate::Architecture;
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticOperationBinary,
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticTemporary,
    SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86Reg};

use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    if matches!(instruction.mnemonic().unwrap_or_default(), "lock cmpxchg8b") {
        return lock_cmpxchg8b(machine, operands);
    }
    if matches!(
        instruction.mnemonic().unwrap_or_default(),
        "lock cmpxchg16b"
    ) {
        return lock_cmpxchg16b(machine, operands);
    }

    match instruction.id() {
        InsnId(id)
            if [
                X86Insn::X86_INS_AAA as u32,
                X86Insn::X86_INS_AAD as u32,
                X86Insn::X86_INS_AAM as u32,
                X86Insn::X86_INS_AAS as u32,
            ]
            .contains(&id) =>
        {
            ascii_adjust(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_NOP as u32 => Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        InsnId(id) if id == X86Insn::X86_INS_MOV as u32 || id == X86Insn::X86_INS_MOVABS as u32 => {
            assign(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_MOVBE as u32 => movbe(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_XCHG as u32 => exchange(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_XADD as u32 => exchange_add(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_CMPXCHG as u32 => compare_exchange(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_CMPXCHG16B as u32 => {
            lock_cmpxchg16b(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_MOVZX as u32 => movx(machine, operands, false),
        InsnId(id)
            if id == X86Insn::X86_INS_MOVSX as u32 || id == X86Insn::X86_INS_MOVSXD as u32 =>
        {
            movx(machine, operands, true)
        }
        InsnId(id) if id == X86Insn::X86_INS_LEA as u32 => lea(machine, operands),
        InsnId(id) if [X86Insn::X86_INS_ADD as u32, X86Insn::X86_INS_SUB as u32].contains(&id) => {
            binary(
                machine,
                instruction,
                operands,
                if id == X86Insn::X86_INS_ADD as u32 {
                    SemanticOperationBinary::Add
                } else {
                    SemanticOperationBinary::Sub
                },
            )
        }
        InsnId(id) if [X86Insn::X86_INS_INC as u32, X86Insn::X86_INS_DEC as u32].contains(&id) => {
            unary(
                machine,
                instruction,
                operands,
                if id == X86Insn::X86_INS_INC as u32 {
                    SemanticOperationBinary::Add
                } else {
                    SemanticOperationBinary::Sub
                },
            )
        }
        InsnId(id) if [X86Insn::X86_INS_NEG as u32, X86Insn::X86_INS_NOT as u32].contains(&id) => {
            unary_op(
                machine,
                instruction,
                operands,
                if id == X86Insn::X86_INS_NEG as u32 {
                    SemanticOperationUnary::Neg
                } else {
                    SemanticOperationUnary::Not
                },
            )
        }
        InsnId(id) if id == X86Insn::X86_INS_BSWAP as u32 => unary_op(
            machine,
            instruction,
            operands,
            SemanticOperationUnary::ByteSwap,
        ),
        InsnId(id) if id == X86Insn::X86_INS_POPCNT as u32 => popcnt(machine, operands),
        InsnId(id) if [X86Insn::X86_INS_CMP as u32].contains(&id) => {
            cmp_like(machine, instruction, operands, "x86.cmp")
        }
        InsnId(id) if id == X86Insn::X86_INS_SBB as u32 => {
            binary(machine, instruction, operands, SemanticOperationBinary::Sub)
        }
        InsnId(id) if id == X86Insn::X86_INS_ADC as u32 => adc(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_ADCX as u32 => adcx_adox(machine, operands, true),
        InsnId(id) if id == X86Insn::X86_INS_ADOX as u32 => adcx_adox(machine, operands, false),
        InsnId(id)
            if [
                X86Insn::X86_INS_CBW as u32,
                X86Insn::X86_INS_CWDE as u32,
                X86Insn::X86_INS_CDQE as u32,
                X86Insn::X86_INS_CWD as u32,
                X86Insn::X86_INS_CDQ as u32,
                X86Insn::X86_INS_CQO as u32,
            ]
            .contains(&id) =>
        {
            sign_extension(machine, instruction)
        }
        InsnId(id) if id == X86Insn::X86_INS_IMUL as u32 => imul(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_MUL as u32 => mul(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_MULX as u32 => mulx(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_DIV as u32 => div(machine, operands, false),
        InsnId(id) if id == X86Insn::X86_INS_IDIV as u32 => div(machine, operands, true),
        _ => None,
    }
}

fn ascii_adjust(
    _machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let al_reg = common::reg(common::reg_id_name(X86Reg::X86_REG_AL as u16), 8);
    let ah_reg = common::reg(common::reg_id_name(X86Reg::X86_REG_AH as u16), 8);
    let al = SemanticExpression::Read(Box::new(al_reg.clone()));
    let ah = SemanticExpression::Read(Box::new(ah_reg.clone()));

    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_AAA as u32 || id == X86Insn::X86_INS_AAS as u32 => {
            let low_nibble = SemanticExpression::Extract {
                arg: Box::new(al.clone()),
                lsb: 0,
                bits: 4,
            };
            let decimal_adjust = common::or(
                common::compare(
                    SemanticOperationCompare::Ugt,
                    low_nibble,
                    SemanticExpression::Const { value: 9, bits: 4 },
                ),
                common::flag_expr("af"),
                1,
            );
            let adjusted_al = if id == X86Insn::X86_INS_AAA as u32 {
                common::add(al.clone(), common::const_u64(6, 8), 8)
            } else {
                common::sub(al.clone(), common::const_u64(6, 8), 8)
            };
            let adjusted_ah = if id == X86Insn::X86_INS_AAA as u32 {
                common::add(ah.clone(), common::const_u64(1, 8), 8)
            } else {
                common::sub(ah.clone(), common::const_u64(1, 8), 8)
            };
            let masked_al = common::and(adjusted_al, common::const_u64(0x0f, 8), 8);
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: al_reg,
                        expression: SemanticExpression::Select {
                            condition: Box::new(decimal_adjust.clone()),
                            when_true: Box::new(masked_al),
                            when_false: Box::new(common::and(al, common::const_u64(0x0f, 8), 8)),
                            bits: 8,
                        },
                    },
                    SemanticEffect::Set {
                        dst: ah_reg,
                        expression: SemanticExpression::Select {
                            condition: Box::new(decimal_adjust.clone()),
                            when_true: Box::new(adjusted_ah),
                            when_false: Box::new(ah),
                            bits: 8,
                        },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: decimal_adjust.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: decimal_adjust,
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        InsnId(id) if id == X86Insn::X86_INS_AAD as u32 => {
            let base = operands
                .first()
                .and_then(|operand| common::operand_expr(_machine, operand))
                .unwrap_or_else(|| common::const_u64(10, 8));
            let ah_term = SemanticExpression::Binary {
                op: SemanticOperationBinary::Mul,
                left: Box::new(ah),
                right: Box::new(base.clone()),
                bits: 8,
            };
            let result = common::add(ah_term, al, 8);
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AL as u16), 8),
                        expression: result.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AH as u16), 8),
                        expression: common::const_u64(0, 8),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: common::compare(
                            SemanticOperationCompare::Eq,
                            result.clone(),
                            common::const_u64(0, 8),
                        ),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: common::extract_bit(result.clone(), 7),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: common::parity_flag(result),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        InsnId(id) if id == X86Insn::X86_INS_AAM as u32 => {
            let base = operands
                .first()
                .and_then(|operand| common::operand_expr(_machine, operand))
                .unwrap_or_else(|| common::const_u64(10, 8));
            let quotient = SemanticExpression::Binary {
                op: SemanticOperationBinary::UDiv,
                left: Box::new(al.clone()),
                right: Box::new(base.clone()),
                bits: 8,
            };
            let remainder = SemanticExpression::Binary {
                op: SemanticOperationBinary::URem,
                left: Box::new(al),
                right: Box::new(base),
                bits: 8,
            };
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AH as u16), 8),
                        expression: quotient,
                    },
                    SemanticEffect::Set {
                        dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AL as u16), 8),
                        expression: remainder.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: common::compare(
                            SemanticOperationCompare::Eq,
                            remainder.clone(),
                            common::const_u64(0, 8),
                        ),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: common::extract_bit(remainder.clone(), 7),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: common::parity_flag(remainder),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        _ => {}
    }
    None
}

fn lock_cmpxchg8b(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let addr = match dst {
        crate::semantics::SemanticLocation::Memory { addr, .. } => *addr,
        _ => return None,
    };
    let eax = common::reg_expr(X86Reg::X86_REG_EAX as u16, 32);
    let edx = common::reg_expr(X86Reg::X86_REG_EDX as u16, 32);
    let ebx = common::reg_expr(X86Reg::X86_REG_EBX as u16, 32);
    let ecx = common::reg_expr(X86Reg::X86_REG_ECX as u16, 32);
    let accumulator = SemanticExpression::Concat {
        parts: vec![edx.clone(), eax.clone()],
        bits: 64,
    };
    let replacement = SemanticExpression::Concat {
        parts: vec![ecx, ebx],
        bits: 64,
    };
    let observed_tmp = crate::semantics::SemanticLocation::Temporary { id: 0, bits: 64 };
    let observed_expr = SemanticExpression::Read(Box::new(observed_tmp.clone()));
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed_expr.clone(),
    );
    let observed_low = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 0,
        bits: 32,
    };
    let observed_high = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 32,
        bits: 32,
    };
    Some(InstructionSemantics {
        version: 1,
        status: crate::semantics::SemanticStatus::Complete,
        temporaries: vec![SemanticTemporary {
            id: 0,
            bits: 64,
            name: Some("lock_cmpxchg8b_observed".to_string()),
        }],
        effects: vec![
            SemanticEffect::AtomicCmpXchg {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr,
                expected: accumulator.clone(),
                desired: replacement,
                bits: 64,
                observed: observed_tmp,
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(eax),
                    when_false: Box::new(observed_low),
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(edx),
                    when_false: Box::new(observed_high),
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: equal,
            },
        ],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

fn lock_cmpxchg16b(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let addr = match dst {
        crate::semantics::SemanticLocation::Memory { addr, .. } => *addr,
        _ => return None,
    };
    let rax = common::reg_expr(X86Reg::X86_REG_RAX as u16, 64);
    let rdx = common::reg_expr(X86Reg::X86_REG_RDX as u16, 64);
    let rbx = common::reg_expr(X86Reg::X86_REG_RBX as u16, 64);
    let rcx = common::reg_expr(X86Reg::X86_REG_RCX as u16, 64);
    let accumulator = SemanticExpression::Concat {
        parts: vec![rdx.clone(), rax.clone()],
        bits: 128,
    };
    let replacement = SemanticExpression::Concat {
        parts: vec![rcx, rbx],
        bits: 128,
    };
    let observed_tmp = crate::semantics::SemanticLocation::Temporary { id: 1, bits: 128 };
    let observed_expr = SemanticExpression::Read(Box::new(observed_tmp.clone()));
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed_expr.clone(),
    );
    let observed_low = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 0,
        bits: 64,
    };
    let observed_high = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 64,
        bits: 64,
    };
    Some(InstructionSemantics {
        version: 1,
        status: crate::semantics::SemanticStatus::Complete,
        temporaries: vec![SemanticTemporary {
            id: 1,
            bits: 128,
            name: Some("lock_cmpxchg16b_observed".to_string()),
        }],
        effects: vec![
            SemanticEffect::AtomicCmpXchg {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr,
                expected: accumulator.clone(),
                desired: replacement,
                bits: 128,
                observed: observed_tmp,
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_RAX as u16), 64),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(rax),
                    when_false: Box::new(observed_low),
                    bits: 64,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_RDX as u16), 64),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(rdx),
                    when_false: Box::new(observed_high),
                    bits: 64,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: equal,
            },
        ],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

fn assign(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let expression = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn movbe(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let expression = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    if !matches!(bits, 16 | 32 | 64) {
        return None;
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::ByteSwap,
                arg: Box::new(expression),
                bits,
            },
        }],
    ))
}

fn exchange(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let left_dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let right_dst = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left_expr = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right_expr = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: left_dst,
                expression: right_expr,
            },
            SemanticEffect::Set {
                dst: right_dst,
                expression: left_expr,
            },
        ],
    ))
}

fn exchange_add(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src_dst = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_expr = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let src_expr = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let result = common::add(dst_expr.clone(), src_expr.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: src_dst,
                expression: dst_expr.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Ult,
                    result.clone(),
                    dst_expr.clone(),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::add_overflow(
                    dst_expr.clone(),
                    src_expr.clone(),
                    result.clone(),
                    bits,
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(dst_expr, src_expr, result, bits),
            },
        ],
    ))
}

fn compare_exchange(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let observed = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let accumulator_reg = match bits {
        8 => X86Reg::X86_REG_AL as u16,
        16 => X86Reg::X86_REG_AX as u16,
        32 => X86Reg::X86_REG_EAX as u16,
        64 => X86Reg::X86_REG_RAX as u16,
        _ => return None,
    };
    let accumulator = common::reg_expr(accumulator_reg, bits);
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed.clone(),
    );
    let diff = common::sub(accumulator.clone(), observed.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: dst.clone(),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(src),
                    when_false: Box::new(observed.clone()),
                    bits,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(accumulator_reg), bits),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(accumulator.clone()),
                    when_false: Box::new(observed.clone()),
                    bits,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: equal.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Ult,
                    accumulator.clone(),
                    observed.clone(),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(diff.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::sub_overflow(
                    accumulator.clone(),
                    observed.clone(),
                    diff.clone(),
                    bits,
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(accumulator, observed, diff, bits),
            },
        ],
    ))
}

fn movx(
    machine: Architecture,
    operands: &[ArchOperand],
    sign_extend: bool,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst_bits = match &dst {
        crate::semantics::SemanticLocation::Register { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Memory { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Flag { bits, .. } => *bits,
        crate::semantics::SemanticLocation::ProgramCounter { bits } => *bits,
        crate::semantics::SemanticLocation::Temporary { bits, .. } => *bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: if sign_extend {
                    SemanticOperationCast::SignExtend
                } else {
                    SemanticOperationCast::ZeroExtend
                },
                arg: Box::new(src),
                bits: dst_bits,
            },
        }],
    ))
}

fn lea(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands.get(1)?;
    let capstone::arch::ArchOperand::X86Operand(op) = src else {
        return None;
    };
    let capstone::arch::x86::X86OperandType::Mem(mem) = op.op_type else {
        return None;
    };
    let base = if mem.base().0 == 0 {
        None
    } else {
        Some(common::reg_expr(
            mem.base().0,
            common::pointer_bits(machine),
        ))
    };
    let index = if mem.index().0 == 0 {
        None
    } else {
        Some((
            common::reg_expr(mem.index().0, common::pointer_bits(machine)),
            mem.scale(),
        ))
    };
    let addr = common::memory_addr(machine, base, index, mem.disp());
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: addr,
        }],
    ))
}

fn binary(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = match &dst {
        crate::semantics::SemanticLocation::Register { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Memory { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Flag { bits, .. } => *bits,
        crate::semantics::SemanticLocation::ProgramCounter { bits } => *bits,
        crate::semantics::SemanticLocation::Temporary { bits, .. } => *bits,
    };
    let result = SemanticExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
        bits,
    };
    let carry = if op == SemanticOperationBinary::Add {
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
    } else {
        common::compare(SemanticOperationCompare::Ult, left.clone(), right.clone())
    };
    let overflow = if op == SemanticOperationBinary::Add {
        common::add_overflow(left.clone(), right.clone(), result.clone(), bits)
    } else {
        common::sub_overflow(left.clone(), right.clone(), result.clone(), bits)
    };
    let auxiliary = common::auxiliary_flag(left.clone(), right.clone(), result.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: carry,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: auxiliary,
            },
        ],
    ))
}

fn adc(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let carry_in = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(common::flag_expr("cf")),
        bits,
    };
    let right_with_carry = common::add(right.clone(), carry_in.clone(), bits);
    let result = common::add(left.clone(), right_with_carry.clone(), bits);
    let carry_out = common::or(
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone()),
        common::and(
            common::flag_expr("cf"),
            common::compare(SemanticOperationCompare::Eq, result.clone(), left.clone()),
            1,
        ),
        1,
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: carry_out,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::add_overflow(
                    left.clone(),
                    right_with_carry.clone(),
                    result.clone(),
                    bits,
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(left, right_with_carry, result, bits),
            },
        ],
    ))
}

fn adcx_adox(
    machine: Architecture,
    operands: &[ArchOperand],
    use_cf: bool,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let carry_flag = if use_cf { "cf" } else { "of" };
    let carry_in_flag = common::flag_expr(carry_flag);
    let carry_in = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(carry_in_flag.clone()),
        bits,
    };
    let right_with_carry = common::add(right.clone(), carry_in, bits);
    let result = common::add(left.clone(), right_with_carry.clone(), bits);
    let carry_out = common::or(
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone()),
        common::and(
            carry_in_flag.clone(),
            common::compare(SemanticOperationCompare::Eq, result.clone(), left.clone()),
            1,
        ),
        1,
    );
    let overflow_out =
        common::add_overflow(left.clone(), right_with_carry.clone(), result.clone(), bits);

    let mut effects = vec![SemanticEffect::Set {
        dst,
        expression: result,
    }];
    if use_cf {
        effects.push(SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: carry_out,
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("of"),
            expression: common::flag_expr("of"),
        });
    } else {
        effects.push(SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: common::flag_expr("cf"),
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("of"),
            expression: overflow_out,
        });
    }
    for flag in ["zf", "sf", "pf", "af"] {
        effects.push(SemanticEffect::Set {
            dst: common::flag(flag),
            expression: common::flag_expr(flag),
        });
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn unary(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = match &dst {
        crate::semantics::SemanticLocation::Register { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Memory { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Flag { bits, .. } => *bits,
        crate::semantics::SemanticLocation::ProgramCounter { bits } => *bits,
        crate::semantics::SemanticLocation::Temporary { bits, .. } => *bits,
    };
    let right = common::const_u64(1, bits);
    let result = SemanticExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
        bits,
    };
    let overflow = if op == SemanticOperationBinary::Add {
        common::add_overflow(left.clone(), right.clone(), result.clone(), bits)
    } else {
        common::sub_overflow(left.clone(), right.clone(), result.clone(), bits)
    };
    let auxiliary = common::auxiliary_flag(left.clone(), right.clone(), result.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: auxiliary,
            },
        ],
    ))
}

fn unary_op(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    op: SemanticOperationUnary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = match &dst {
        crate::semantics::SemanticLocation::Register { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Memory { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Flag { bits, .. } => *bits,
        crate::semantics::SemanticLocation::ProgramCounter { bits } => *bits,
        crate::semantics::SemanticLocation::Temporary { bits, .. } => *bits,
    };
    let expression = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_NEG as u32) {
        let zero = common::const_u64(0, bits);
        let result = SemanticExpression::Unary {
            op,
            arg: Box::new(expression.clone()),
            bits,
        };
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![
                SemanticEffect::Set {
                    dst,
                    expression: result.clone(),
                },
                SemanticEffect::Set {
                    dst: common::flag("cf"),
                    expression: common::compare(
                        SemanticOperationCompare::Ne,
                        expression.clone(),
                        zero.clone(),
                    ),
                },
                SemanticEffect::Set {
                    dst: common::flag("zf"),
                    expression: common::compare(SemanticOperationCompare::Eq, result.clone(), zero),
                },
                SemanticEffect::Set {
                    dst: common::flag("sf"),
                    expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
                },
                SemanticEffect::Set {
                    dst: common::flag("of"),
                    expression: common::compare(
                        SemanticOperationCompare::Eq,
                        expression.clone(),
                        common::const_u64(1u64 << (bits.saturating_sub(1)), bits),
                    ),
                },
                SemanticEffect::Set {
                    dst: common::flag("pf"),
                    expression: common::parity_flag(result.clone()),
                },
                SemanticEffect::Set {
                    dst: common::flag("af"),
                    expression: common::auxiliary_flag(
                        common::const_u64(0, bits),
                        expression,
                        result,
                        bits,
                    ),
                },
            ],
        ));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op,
                arg: Box::new(expression),
                bits,
            },
        }],
    ))
}

fn popcnt(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let result = SemanticExpression::Unary {
        op: SemanticOperationUnary::PopCount,
        arg: Box::new(src.clone()),
        bits,
    };
    let src_is_zero = common::compare(
        SemanticOperationCompare::Eq,
        src,
        common::const_u64(0, bits),
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result,
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: src_is_zero,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

fn cmp_like(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
    _name: &str,
) -> Option<InstructionSemantics> {
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))
        .map(|location| common::location_bits(&location))
        .unwrap_or_else(|| common::pointer_bits(machine));
    let diff = common::sub(left.clone(), right.clone(), bits);
    let sign_bit = bits.saturating_sub(1);
    let zf = common::compare(SemanticOperationCompare::Eq, left.clone(), right.clone());
    let cf = common::compare(SemanticOperationCompare::Ult, left.clone(), right.clone());
    let sf = common::extract_bit(diff.clone(), sign_bit);
    let of = common::sub_overflow(left.clone(), right.clone(), diff.clone(), bits);
    let af = common::auxiliary_flag(left.clone(), right.clone(), diff.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: zf,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: cf,
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: sf,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: of,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: af,
            },
        ],
    ))
}

fn sign_extension(_machine: Architecture, instruction: &Insn) -> Option<InstructionSemantics> {
    let (src_reg, src_bits, dst_reg, dst_bits, high_only) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_CBW as u32 => (
            X86Reg::X86_REG_AL as u16,
            8,
            X86Reg::X86_REG_AX as u16,
            16,
            false,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CWDE as u32 => (
            X86Reg::X86_REG_AX as u16,
            16,
            X86Reg::X86_REG_EAX as u16,
            32,
            false,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CDQE as u32 => (
            X86Reg::X86_REG_EAX as u16,
            32,
            X86Reg::X86_REG_RAX as u16,
            64,
            false,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CWD as u32 => (
            X86Reg::X86_REG_AX as u16,
            16,
            X86Reg::X86_REG_DX as u16,
            16,
            true,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CDQ as u32 => (
            X86Reg::X86_REG_EAX as u16,
            32,
            X86Reg::X86_REG_EDX as u16,
            32,
            true,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CQO as u32 => (
            X86Reg::X86_REG_RAX as u16,
            64,
            X86Reg::X86_REG_RDX as u16,
            64,
            true,
        ),
        _ => return None,
    };

    let src = common::reg_expr(src_reg, src_bits);
    let expression = if high_only {
        SemanticExpression::Select {
            condition: Box::new(common::extract_bit(src, src_bits - 1)),
            when_true: Box::new(common::const_u64(u64::MAX, dst_bits)),
            when_false: Box::new(common::const_u64(0, dst_bits)),
            bits: dst_bits,
        }
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(src),
            bits: dst_bits,
        }
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(dst_reg), dst_bits),
            expression,
        }],
    ))
}

fn imul(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    match operands.len() {
        2 | 3 => imul_explicit(machine, operands),
        1 => imul_implicit(machine, operands),
        _ => None,
    }
}

fn imul_explicit(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let full_bits = bits.saturating_mul(2);
    let left = if operands.len() == 2 {
        operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))?
    } else {
        operands
            .get(1)
            .and_then(|operand| common::operand_expr(machine, operand))?
    };
    let right = operands
        .last()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(left),
            bits: full_bits,
        }),
        right: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(right),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let low = SemanticExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits,
    };
    let high = SemanticExpression::Extract {
        arg: Box::new(wide_product),
        lsb: bits,
        bits,
    };
    let sign_fill = signed_extension_fill(low.clone(), bits);
    let overflow = common::compare(SemanticOperationCompare::Ne, high, sign_fill);

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: low.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: overflow.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn imul_implicit(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_reg, high_reg, acc_reg, result_bits) = implicit_mul_registers(machine, bits)?;
    let full_bits = bits.saturating_mul(2);
    let acc = common::reg_expr(acc_reg, bits);
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(acc),
            bits: full_bits,
        }),
        right: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let result_low = SemanticExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits: result_bits,
    };
    let overflow = if bits == 8 {
        common::compare(
            SemanticOperationCompare::Ne,
            SemanticExpression::Extract {
                arg: Box::new(wide_product),
                lsb: 8,
                bits: 8,
            },
            signed_extension_fill(
                SemanticExpression::Extract {
                    arg: Box::new(result_low.clone()),
                    lsb: 0,
                    bits: 8,
                },
                8,
            ),
        )
    } else {
        let high = SemanticExpression::Extract {
            arg: Box::new(wide_product),
            lsb: bits,
            bits,
        };
        common::compare(
            SemanticOperationCompare::Ne,
            high,
            signed_extension_fill(
                SemanticExpression::Extract {
                    arg: Box::new(result_low.clone()),
                    lsb: 0,
                    bits,
                },
                bits,
            ),
        )
    };

    let mut effects = vec![SemanticEffect::Set {
        dst: common::reg(common::reg_id_name(low_reg), result_bits),
        expression: result_low,
    }];
    if bits > 8 {
        effects.push(SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(high_reg), bits),
            expression: SemanticExpression::Extract {
                arg: Box::new(SemanticExpression::Binary {
                    op: SemanticOperationBinary::Mul,
                    left: Box::new(SemanticExpression::Cast {
                        op: SemanticOperationCast::SignExtend,
                        arg: Box::new(common::reg_expr(acc_reg, bits)),
                        bits: full_bits,
                    }),
                    right: Box::new(SemanticExpression::Cast {
                        op: SemanticOperationCast::SignExtend,
                        arg: Box::new(
                            operands
                                .first()
                                .and_then(|operand| common::operand_expr(machine, operand))
                                .unwrap(),
                        ),
                        bits: full_bits,
                    }),
                    bits: full_bits,
                }),
                lsb: bits,
                bits,
            },
        });
    }
    effects.extend([
        SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: overflow.clone(),
        },
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: overflow,
        },
        SemanticEffect::Set {
            dst: common::flag("zf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("pf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
    ]);

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn mul(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_reg, high_reg, acc_reg, result_bits) = implicit_mul_registers(machine, bits)?;
    let full_bits = bits.saturating_mul(2);
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(common::reg_expr(acc_reg, bits)),
            bits: full_bits,
        }),
        right: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let result_low = SemanticExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits: result_bits,
    };
    let high_nonzero = if bits == 8 {
        common::compare(
            SemanticOperationCompare::Ne,
            SemanticExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: 8,
                bits: 8,
            },
            common::const_u64(0, 8),
        )
    } else {
        common::compare(
            SemanticOperationCompare::Ne,
            SemanticExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: bits,
                bits,
            },
            common::const_u64(0, bits),
        )
    };

    let mut effects = vec![SemanticEffect::Set {
        dst: common::reg(common::reg_id_name(low_reg), result_bits),
        expression: result_low,
    }];
    if bits > 8 {
        effects.push(SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(high_reg), bits),
            expression: SemanticExpression::Extract {
                arg: Box::new(wide_product),
                lsb: bits,
                bits,
            },
        });
    }
    effects.extend([
        SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: high_nonzero.clone(),
        },
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: high_nonzero,
        },
        SemanticEffect::Set {
            dst: common::flag("zf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("pf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
    ]);

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn mulx(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst_low = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_high = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst_low);
    if common::location_bits(&dst_high) != bits || !matches!(bits, 32 | 64) {
        return None;
    }

    let implicit = match bits {
        32 => common::reg_expr(X86Reg::X86_REG_EDX as u16, 32),
        64 => common::reg_expr(X86Reg::X86_REG_RDX as u16, 64),
        _ => return None,
    };
    let full_bits = bits * 2;
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(implicit),
            bits: full_bits,
        }),
        right: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: dst_low,
                expression: SemanticExpression::Extract {
                    arg: Box::new(wide_product.clone()),
                    lsb: 0,
                    bits,
                },
            },
            SemanticEffect::Set {
                dst: dst_high,
                expression: SemanticExpression::Extract {
                    arg: Box::new(wide_product),
                    lsb: bits,
                    bits,
                },
            },
        ],
    ))
}

fn div(
    machine: Architecture,
    operands: &[ArchOperand],
    signed: bool,
) -> Option<InstructionSemantics> {
    let divisor = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_reg, high_reg, acc_reg, result_bits) = implicit_mul_registers(machine, bits)?;
    let dividend = if bits == 8 {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(common::reg_expr(low_reg, result_bits)),
            bits: 16,
        }
    } else {
        SemanticExpression::Concat {
            parts: vec![
                common::reg_expr(high_reg, bits),
                common::reg_expr(acc_reg, bits),
            ],
            bits: bits * 2,
        }
    };
    let full_bits = bits * 2;
    let divisor_wide = if signed {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(divisor),
            bits: full_bits,
        }
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(divisor),
            bits: full_bits,
        }
    };
    let quotient = SemanticExpression::Binary {
        op: if signed {
            SemanticOperationBinary::SDiv
        } else {
            SemanticOperationBinary::UDiv
        },
        left: Box::new(dividend.clone()),
        right: Box::new(divisor_wide.clone()),
        bits: full_bits,
    };
    let remainder = SemanticExpression::Binary {
        op: if signed {
            SemanticOperationBinary::SRem
        } else {
            SemanticOperationBinary::URem
        },
        left: Box::new(dividend),
        right: Box::new(divisor_wide),
        bits: full_bits,
    };
    let q_bits = if bits == 8 { 8 } else { bits };
    let r_bits = if bits == 8 { 8 } else { bits };
    let q_reg = if bits == 8 {
        X86Reg::X86_REG_AL as u16
    } else {
        acc_reg
    };
    let r_reg = if bits == 8 {
        X86Reg::X86_REG_AH as u16
    } else {
        high_reg
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(q_reg), q_bits),
                expression: SemanticExpression::Extract {
                    arg: Box::new(quotient),
                    lsb: 0,
                    bits: q_bits,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(r_reg), r_bits),
                expression: SemanticExpression::Extract {
                    arg: Box::new(remainder),
                    lsb: 0,
                    bits: r_bits,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn implicit_mul_registers(machine: Architecture, bits: u16) -> Option<(u16, u16, u16, u16)> {
    match bits {
        8 => Some((
            X86Reg::X86_REG_AX as u16,
            X86Reg::X86_REG_AH as u16,
            X86Reg::X86_REG_AL as u16,
            16,
        )),
        16 => Some((
            X86Reg::X86_REG_AX as u16,
            X86Reg::X86_REG_DX as u16,
            X86Reg::X86_REG_AX as u16,
            16,
        )),
        32 => Some((
            X86Reg::X86_REG_EAX as u16,
            X86Reg::X86_REG_EDX as u16,
            X86Reg::X86_REG_EAX as u16,
            32,
        )),
        64 if machine == Architecture::AMD64 => Some((
            X86Reg::X86_REG_RAX as u16,
            X86Reg::X86_REG_RDX as u16,
            X86Reg::X86_REG_RAX as u16,
            64,
        )),
        _ => None,
    }
}

fn operand_bits(machine: Architecture, operand: &ArchOperand) -> Option<u16> {
    let location = common::operand_location(machine, operand)?;
    Some(common::location_bits(&location))
}

fn signed_extension_fill(value: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Select {
        condition: Box::new(common::extract_bit(value, bits - 1)),
        when_true: Box::new(common::const_u64(u64::MAX, bits)),
        when_false: Box::new(common::const_u64(0, bits)),
        bits,
    }
}
