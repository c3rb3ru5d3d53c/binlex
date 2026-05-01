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

use crate::semantics::architectures::arm64::Arm64InstructionView;
use crate::semantics::architectures::arm64::helpers::{
    binary, complete, const_u64, location_bits, sign_extend_to_bits, truncate_to_bits,
    zero_extend_to_bits,
};
use crate::semantics::architectures::arm64::{Arm64OperandKind, Arm64OperandView};
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticLocation, SemanticOperationBinary, SemanticTerminator,
};

pub(crate) fn build(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    match view.mnemonic.as_str() {
        // Single-transfer forms now use the normalized memory operand plus the
        // optional writeback operand so pre/post-indexed addressing can stay in
        // the architecture-owned path.
        "ldp" | "ldnp" if view.operand_count >= 3 => build_load_pair(view),
        "ldpsw" if view.operand_count >= 3 => build_load_pair_signed_word(view),
        "stp" | "stnp" if view.operand_count >= 3 => build_store_pair(view),
        "ldr" | "ldur" if view.operand_count >= 2 => build_load(view, LoadKind::FullWidth, None),
        "ldrb" | "ldurb" if view.operand_count >= 2 => {
            build_load(view, LoadKind::ZeroExtend, Some(8))
        }
        "ldrh" | "ldurh" if view.operand_count >= 2 => {
            build_load(view, LoadKind::ZeroExtend, Some(16))
        }
        "ldrsb" | "ldursb" if view.operand_count >= 2 => {
            build_load(view, LoadKind::SignExtend, Some(8))
        }
        "ldrsh" | "ldursh" if view.operand_count >= 2 => {
            build_load(view, LoadKind::SignExtend, Some(16))
        }
        "ldrsw" | "ldursw" if view.operand_count >= 2 => {
            build_load(view, LoadKind::SignExtend, Some(32))
        }
        "str" | "stur" if view.operand_count >= 2 => build_store(view, None),
        "strb" | "sturb" if view.operand_count >= 2 => build_store(view, Some(8)),
        "strh" | "sturh" if view.operand_count >= 2 => build_store(view, Some(16)),
        // Base-plus-immediate forms like ldtr/sttr that often surface as
        // register + base + displacement instead of a single memory operand.
        "ldtr" if view.operand_count >= 2 => {
            build_load_base_immediate(view, LoadKind::FullWidth, None)
        }
        "ldtrb" if view.operand_count >= 2 => {
            build_load_base_immediate(view, LoadKind::ZeroExtend, Some(8))
        }
        "ldtrh" if view.operand_count >= 2 => {
            build_load_base_immediate(view, LoadKind::ZeroExtend, Some(16))
        }
        "ldtrsb" if view.operand_count >= 2 => {
            build_load_base_immediate(view, LoadKind::SignExtend, Some(8))
        }
        "ldtrsh" if view.operand_count >= 2 => {
            build_load_base_immediate(view, LoadKind::SignExtend, Some(16))
        }
        "ldtrsw" if view.operand_count >= 2 => {
            build_load_base_immediate(view, LoadKind::SignExtend, Some(32))
        }
        "sttr" if view.operand_count >= 2 => build_store_base_immediate(view, None),
        "sttrb" if view.operand_count >= 2 => build_store_base_immediate(view, Some(8)),
        "sttrh" if view.operand_count >= 2 => build_store_base_immediate(view, Some(16)),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum LoadKind {
    FullWidth,
    ZeroExtend,
    SignExtend,
}

fn build_load(
    view: &Arm64InstructionView,
    kind: LoadKind,
    load_bits: Option<u16>,
) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let addr = effective_memory_address(view, view.operand(1)?, view.operand(2))?;
    let dst_bits = location_bits(&dst);
    let expression = match kind {
        LoadKind::FullWidth => SemanticExpression::Load {
            space: SemanticAddressSpace::Default,
            addr: Box::new(addr),
            bits: dst_bits,
        },
        LoadKind::ZeroExtend => zero_extend_to_bits(
            SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: load_bits?,
            },
            dst_bits,
        ),
        LoadKind::SignExtend => sign_extend_to_bits(
            SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: load_bits?,
            },
            dst_bits,
        ),
    };

    let mut effects = vec![SemanticEffect::Set { dst, expression }];
    if let Some(writeback) = writeback_effect(view, view.operand(1)?, view.operand(2)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_store(
    view: &Arm64InstructionView,
    store_bits: Option<u16>,
) -> Option<InstructionSemantics> {
    let src = operand_expression(view.operand(0)?)?;
    let addr = effective_memory_address(view, view.operand(1)?, view.operand(2))?;
    let expression = match store_bits {
        Some(bits) => truncate_to_bits(src, bits),
        None => src.clone(),
    };
    let bits = store_bits.unwrap_or_else(|| expression.bits());

    let mut effects = vec![SemanticEffect::Store {
        space: SemanticAddressSpace::Default,
        addr,
        expression,
        bits,
    }];
    if let Some(writeback) = writeback_effect(view, view.operand(1)?, view.operand(2)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_load_pair(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let first_dst = register_location(view.operand(0)?)?;
    let second_dst = register_location(view.operand(1)?)?;
    let base_addr = effective_memory_address(view, view.operand(2)?, view.operand(3))?;
    let stride = (location_bits(&first_dst) / 8) as u64;
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
                bits: location_bits(&first_dst),
            },
        },
        SemanticEffect::Set {
            dst: second_dst.clone(),
            expression: SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(second_addr),
                bits: location_bits(&second_dst),
            },
        },
    ];

    if let Some(writeback) = writeback_effect(view, view.operand(2)?, view.operand(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_load_pair_signed_word(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let first_dst = register_location(view.operand(0)?)?;
    let second_dst = register_location(view.operand(1)?)?;
    let base_addr = effective_memory_address(view, view.operand(2)?, view.operand(3))?;
    let second_addr = binary(
        SemanticOperationBinary::Add,
        base_addr.clone(),
        const_u64(4, 64),
        64,
    );

    let mut effects = vec![
        SemanticEffect::Set {
            dst: first_dst.clone(),
            expression: sign_extend_to_bits(
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(base_addr),
                    bits: 32,
                },
                location_bits(&first_dst),
            ),
        },
        SemanticEffect::Set {
            dst: second_dst.clone(),
            expression: sign_extend_to_bits(
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(second_addr),
                    bits: 32,
                },
                location_bits(&second_dst),
            ),
        },
    ];

    if let Some(writeback) = writeback_effect(view, view.operand(2)?, view.operand(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn build_store_pair(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let first_src = operand_expression(view.operand(0)?)?;
    let second_src = operand_expression(view.operand(1)?)?;
    let base_addr = effective_memory_address(view, view.operand(2)?, view.operand(3))?;
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

    if let Some(writeback) = writeback_effect(view, view.operand(2)?, view.operand(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_load_base_immediate(
    view: &Arm64InstructionView,
    kind: LoadKind,
    load_bits: Option<u16>,
) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let addr = base_immediate_address(view.operand(1)?, view.operand(2))?;
    let dst_bits = location_bits(&dst);
    let expression = match kind {
        LoadKind::FullWidth => SemanticExpression::Load {
            space: SemanticAddressSpace::Default,
            addr: Box::new(addr),
            bits: dst_bits,
        },
        LoadKind::ZeroExtend => zero_extend_to_bits(
            SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: load_bits?,
            },
            dst_bits,
        ),
        LoadKind::SignExtend => sign_extend_to_bits(
            SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: load_bits?,
            },
            dst_bits,
        ),
    };

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_store_base_immediate(
    view: &Arm64InstructionView,
    store_bits: Option<u16>,
) -> Option<InstructionSemantics> {
    let src = operand_expression(view.operand(0)?)?;
    let addr = base_immediate_address(view.operand(1)?, view.operand(2))?;
    let expression = match store_bits {
        Some(bits) => truncate_to_bits(src, bits),
        None => src.clone(),
    };
    let bits = store_bits.unwrap_or_else(|| expression.bits());

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Store {
            space: SemanticAddressSpace::Default,
            addr,
            expression,
            bits,
        }],
    ))
}

pub(super) fn register_location(operand: &Arm64OperandView) -> Option<SemanticLocation> {
    if operand.kind != Arm64OperandKind::Register {
        return None;
    }
    Some(SemanticLocation::Register {
        name: operand.register_name()?.to_string(),
        bits: operand_bits(operand),
    })
}

pub(super) fn operand_expression(operand: &Arm64OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        Arm64OperandKind::Register => Some(SemanticExpression::Read(Box::new(
            SemanticLocation::Register {
                name: operand.register_name()?.to_string(),
                bits: operand_bits(operand),
            },
        ))),
        Arm64OperandKind::Immediate => Some(const_u64(
            operand.immediate_value()? as i64 as u64,
            operand_bits(operand),
        )),
        Arm64OperandKind::Memory => Some(SemanticExpression::Load {
            space: SemanticAddressSpace::Default,
            addr: Box::new(memory_address(operand)?),
            bits: 64,
        }),
        _ => None,
    }
}

fn memory_address(operand: &Arm64OperandView) -> Option<SemanticExpression> {
    let mem = operand.memory_operand()?;

    let mut address = mem.base_register_name.as_ref().map(|name| {
        SemanticExpression::Read(Box::new(SemanticLocation::Register {
            name: name.clone(),
            bits: 64,
        }))
    });

    if let Some(index_name) = mem.index_register_name.as_ref() {
        let index = SemanticExpression::Read(Box::new(SemanticLocation::Register {
            name: index_name.clone(),
            bits: 64,
        }));
        address = Some(match address {
            Some(base) => binary(SemanticOperationBinary::Add, base, index, 64),
            None => index,
        });
    }

    let address = address.unwrap_or_else(|| const_u64(0, 64));
    if mem.displacement == 0 {
        Some(address)
    } else {
        Some(binary(
            SemanticOperationBinary::Add,
            address,
            const_u64(mem.displacement as i64 as u64, 64),
            64,
        ))
    }
}

fn base_register_address(operand: &Arm64OperandView) -> Option<SemanticExpression> {
    let mem = operand.memory_operand()?;
    let name = mem.base_register_name.as_ref()?;
    Some(SemanticExpression::Read(Box::new(
        SemanticLocation::Register {
            name: name.clone(),
            bits: 64,
        },
    )))
}

pub(super) fn effective_memory_address(
    view: &Arm64InstructionView,
    mem_operand: &Arm64OperandView,
    writeback_operand: Option<&Arm64OperandView>,
) -> Option<SemanticExpression> {
    if is_post_indexed(view, writeback_operand) {
        return base_register_address(mem_operand);
    }
    memory_address(mem_operand)
}

fn base_immediate_address(
    base_operand: &Arm64OperandView,
    displacement_operand: Option<&Arm64OperandView>,
) -> Option<SemanticExpression> {
    if base_operand.kind == Arm64OperandKind::Memory {
        return memory_address(base_operand);
    }

    let base = operand_expression(base_operand)?;
    let displacement = displacement_operand
        .and_then(Arm64OperandView::immediate_value)
        .unwrap_or(0);
    if displacement == 0 {
        Some(base)
    } else {
        Some(binary(
            SemanticOperationBinary::Add,
            base,
            const_u64(displacement as i64 as u64, 64),
            64,
        ))
    }
}

pub(super) fn writeback_effect(
    view: &Arm64InstructionView,
    mem_operand: &Arm64OperandView,
    writeback_operand: Option<&Arm64OperandView>,
) -> Option<SemanticEffect> {
    let mem = mem_operand.memory_operand()?;
    let base_name = mem.base_register_name.as_ref()?;
    if !view
        .operand_text
        .as_deref()
        .is_some_and(|op_str| op_str.contains("],") || op_str.contains("]!"))
        && writeback_operand
            .and_then(Arm64OperandView::immediate_value)
            .is_none()
    {
        return None;
    }
    let delta = writeback_operand
        .and_then(Arm64OperandView::immediate_value)
        .unwrap_or(mem.displacement as i64) as u64;
    if delta == 0 {
        return None;
    }
    let base = SemanticLocation::Register {
        name: base_name.clone(),
        bits: 64,
    };
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

fn is_post_indexed(
    view: &Arm64InstructionView,
    writeback_operand: Option<&Arm64OperandView>,
) -> bool {
    writeback_operand.is_some()
        || view
            .operand_text
            .as_deref()
            .is_some_and(|op_str| op_str.contains("],"))
}

fn operand_bits(operand: &Arm64OperandView) -> u16 {
    if operand.size_bits == 0 {
        64
    } else {
        operand.size_bits
    }
}
