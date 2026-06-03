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

use crate::ir::lir::arm64::InstructionDetailArm64;
use crate::ir::lir::arm64::builders::memory::{
    build_load_pair, effective_memory_address, operand_expression, register_location,
    writeback_effect,
};
use crate::ir::lir::arm64::helpers::{
    complete, location_bits, truncate_to_bits, zero_extend_to_bits,
};
use crate::ir::lir::{
    Lir, LirAddressSpace, LirEffect, LirExpression, LirLocation, LirStatus, LirTemporary,
    LirTerminator,
};

pub(crate) fn build(view: &InstructionDetailArm64) -> Option<Lir> {
    match view.mnemonic.as_str() {
        "ldaxp" | "ldxp" if view.operand_count >= 3 => build_load_pair(view),
        "ldar" | "ldapr" if view.operand_count >= 2 => build_full_width_load(view),
        "ldarb" | "ldaprb" if view.operand_count >= 2 => build_zero_extend_load(view, 8),
        "ldarh" if view.operand_count >= 2 => build_zero_extend_load(view, 16),
        "ldaxr" | "ldxr" if view.operand_count >= 2 => build_exclusive_load(view, None),
        "ldaxrb" | "ldxrb" if view.operand_count >= 2 => build_exclusive_load(view, Some(8)),
        "ldaxrh" | "ldxrh" if view.operand_count >= 2 => build_exclusive_load(view, Some(16)),
        "stlr" if view.operand_count >= 2 => build_store(view, None),
        "stlrb" if view.operand_count >= 2 => build_store(view, Some(8)),
        "stlrh" if view.operand_count >= 2 => build_store(view, Some(16)),
        "cas" | "casa" | "casal" | "casl" | "casab" | "casalb" | "casb" | "caslb" | "casah"
        | "casalh" | "cash" | "caslh"
            if view.operand_count >= 3 =>
        {
            build_cas(view)
        }
        "casp" | "caspa" | "caspal" | "caspl" if view.operand_count >= 5 => build_casp(view),
        "ldaddal" | "ldset" => build_intrinsic_fallthrough(view),
        "stlxr" | "stlxrb" | "stlxrh" | "stxr" | "stxrb" | "stxrh" | "stxp" | "stlxp"
            if view.operand_count >= 1 =>
        {
            build_effect_intrinsic(view)
        }
        _ => None,
    }
}

fn build_full_width_load(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let addr = effective_memory_address(view, view.operand(1)?, view.operand(2))?;
    let mut effects = vec![LirEffect::Set {
        dst: dst.clone(),
        expression: LirExpression::Load {
            space: LirAddressSpace::Default,
            addr: Box::new(addr),
            bits: location_bits(&dst),
        },
    }];
    if let Some(writeback) = writeback_effect(view, view.operand(1)?, view.operand(2)) {
        effects.push(writeback);
    }
    Some(complete(LirTerminator::FallThrough, effects))
}

fn build_zero_extend_load(view: &InstructionDetailArm64, load_bits: u16) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let addr = effective_memory_address(view, view.operand(1)?, view.operand(2))?;
    let mut effects = vec![LirEffect::Set {
        dst: dst.clone(),
        expression: zero_extend_to_bits(
            LirExpression::Load {
                space: LirAddressSpace::Default,
                addr: Box::new(addr),
                bits: load_bits,
            },
            location_bits(&dst),
        ),
    }];
    if let Some(writeback) = writeback_effect(view, view.operand(1)?, view.operand(2)) {
        effects.push(writeback);
    }
    Some(complete(LirTerminator::FallThrough, effects))
}

fn build_exclusive_load(view: &InstructionDetailArm64, load_bits: Option<u16>) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let addr = effective_memory_address(view, view.operand(1)?, view.operand(2))?;
    let expression = match load_bits {
        None => LirExpression::Load {
            space: LirAddressSpace::Default,
            addr: Box::new(addr.clone()),
            bits: location_bits(&dst),
        },
        Some(bits) => zero_extend_to_bits(
            LirExpression::Load {
                space: LirAddressSpace::Default,
                addr: Box::new(addr.clone()),
                bits,
            },
            location_bits(&dst),
        ),
    };
    Some(complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set { dst, expression },
            LirEffect::Intrinsic {
                name: format!("arm64.{}.monitor", view.mnemonic),
                args: vec![addr],
                outputs: Vec::new(),
            },
        ],
    ))
}

fn build_store(view: &InstructionDetailArm64, store_bits: Option<u16>) -> Option<Lir> {
    let src = operand_expression(view.operand(0)?)?;
    let addr = effective_memory_address(view, view.operand(1)?, view.operand(2))?;
    let expression = match store_bits {
        Some(bits) => truncate_to_bits(src, bits),
        None => src.clone(),
    };
    let bits = store_bits.unwrap_or_else(|| expression.bits());

    let mut effects = vec![LirEffect::Store {
        space: LirAddressSpace::Default,
        addr,
        expression,
        bits,
    }];
    if let Some(writeback) = writeback_effect(view, view.operand(1)?, view.operand(2)) {
        effects.push(writeback);
    }
    Some(complete(LirTerminator::FallThrough, effects))
}

fn build_effect_intrinsic(view: &InstructionDetailArm64) -> Option<Lir> {
    let outputs = view
        .operand(0)
        .and_then(register_location)
        .map(|dst| vec![dst])
        .unwrap_or_default();
    let args = view
        .operands()
        .iter()
        .skip(1)
        .filter_map(operand_expression)
        .collect();
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Intrinsic {
            name: format!("arm64.{}", view.mnemonic),
            args,
            outputs,
        }],
    ))
}

fn build_intrinsic_fallthrough(view: &InstructionDetailArm64) -> Option<Lir> {
    let outputs = view
        .operand(0)
        .and_then(register_location)
        .map(|dst| vec![dst]);
    let args = view
        .operands()
        .iter()
        .filter_map(operand_expression)
        .collect();
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Intrinsic {
            name: format!("arm64.{}", view.mnemonic),
            args,
            outputs: outputs.unwrap_or_default(),
        }],
    ))
}

fn build_cas(view: &InstructionDetailArm64) -> Option<Lir> {
    let observed = register_location(view.operand(0)?)?;
    let expected = operand_expression(view.operand(0)?)?;
    let desired = operand_expression(view.operand(1)?)?;
    let addr = effective_memory_address(view, view.operand(2)?, view.operand(3))?;
    let bits = match view.mnemonic.as_str() {
        "casab" | "casalb" | "casb" | "caslb" => 8,
        "casah" | "casalh" | "cash" | "caslh" => 16,
        _ => location_bits(&observed).min(64),
    };
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::AtomicCmpXchg {
            space: LirAddressSpace::Default,
            addr,
            expected: truncate_to_bits(expected, bits),
            desired: truncate_to_bits(desired, bits),
            bits,
            observed,
        }],
    ))
}

fn build_casp(view: &InstructionDetailArm64) -> Option<Lir> {
    let observed_low = register_location(view.operand(0)?)?;
    let observed_high = register_location(view.operand(1)?)?;
    let expected_low = operand_expression(view.operand(0)?)?;
    let expected_high = operand_expression(view.operand(1)?)?;
    let desired_low = operand_expression(view.operand(2)?)?;
    let desired_high = operand_expression(view.operand(3)?)?;
    let addr = effective_memory_address(view, view.operand(4)?, view.operand(5))?;
    let element_bits = location_bits(&observed_low);
    let total_bits = element_bits.checked_mul(2)?;
    let temp_id = 0u32;
    let temp_location = LirLocation::Temporary {
        id: temp_id,
        bits: total_bits,
    };
    let temp_expr = LirExpression::Read(Box::new(temp_location.clone()));
    Some(Lir {
        version: 1,
        status: LirStatus::Complete,
        metadata: Default::default(),
        abi: None,
        encoding: None,
        temporaries: vec![LirTemporary {
            id: temp_id,
            bits: total_bits,
            name: Some(format!("arm64_{}", view.mnemonic)),
        }],
        effects: vec![
            LirEffect::AtomicCmpXchg {
                space: LirAddressSpace::Default,
                addr,
                expected: LirExpression::Concat {
                    parts: vec![expected_high, expected_low],
                    bits: total_bits,
                },
                desired: LirExpression::Concat {
                    parts: vec![desired_high, desired_low],
                    bits: total_bits,
                },
                bits: total_bits,
                observed: temp_location,
            },
            LirEffect::Set {
                dst: observed_low,
                expression: LirExpression::Extract {
                    arg: Box::new(temp_expr.clone()),
                    lsb: 0,
                    bits: element_bits,
                },
            },
            LirEffect::Set {
                dst: observed_high,
                expression: LirExpression::Extract {
                    arg: Box::new(temp_expr),
                    lsb: element_bits,
                    bits: element_bits,
                },
            },
        ],
        terminator: LirTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}
