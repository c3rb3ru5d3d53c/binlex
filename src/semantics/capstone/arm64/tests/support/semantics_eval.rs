use std::collections::BTreeMap;

use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticOperationUnary, SemanticTerminator,
};

use super::common::semantics;
use super::fixtures::{Arm64CpuState, Arm64Execution, Arm64Fixture, Arm64Transition};
use super::unicorn::{ARM64_CODE_ADDRESS, semantic_name_for_arch_register, unicorn_arm64_execution};

pub(crate) fn assert_arm64_semantics_match_unicorn(name: &str, bytes: &[u8], fixture: Arm64Fixture) {
    let semantics = semantics(name, bytes);
    let tracked_registers = tracked_registers(&semantics, &fixture);
    let vector_register_writes = written_locations(&semantics)
        .into_iter()
        .filter(|name| is_vector_semantic_register(name))
        .collect::<Vec<_>>();
    let interpreted = interpret_arm64_semantics(bytes, &semantics, &fixture, &tracked_registers);
    let unicorn = unicorn_arm64_execution(
        name,
        bytes,
        &fixture,
        &tracked_registers,
        &interpreted.memory_writes,
        &vector_register_writes,
    );

    assert_eq!(
        unicorn.transition.pre, interpreted.transition.pre,
        "{name}: semantics pre-state diverged from unicorn pre-state"
    );
    assert_eq!(
        unicorn.transition.post.pc, interpreted.transition.post.pc,
        "{name}: pc mismatch\nunicorn: {:#x}\nsemantics: {:#x}",
        unicorn.transition.post.pc, interpreted.transition.post.pc
    );

    for register in written_locations(&semantics) {
        if is_vector_semantic_register(&register) {
            let expected = interpreted
                .transition
                .post
                .registers
                .get(&register)
                .copied()
                .unwrap_or_default()
                .to_le_bytes();
            let Some(base) = vector_spill_address(&register) else {
                panic!("{name}: missing vector spill address for {register}");
            };
            for (offset, expected_byte) in expected.into_iter().enumerate() {
                let byte_address = base + offset as u64;
                let unicorn_value = unicorn
                    .transition
                    .post
                    .memory
                    .get(&byte_address)
                    .copied()
                    .unwrap_or_default();
                assert_eq!(
                    unicorn_value, expected_byte,
                    "{name}: vector byte mismatch for {register} at 0x{byte_address:x}\nunicorn: {:#04x}\nsemantics: {:#04x}",
                    unicorn_value, expected_byte
                );
            }
            continue;
        }
        let unicorn_value = unicorn
            .transition
            .post
            .registers
            .get(&register)
            .copied()
            .unwrap_or_default();
        let interpreted_value = interpreted
            .transition
            .post
            .registers
            .get(&register)
            .copied()
            .unwrap_or_default();
        assert_eq!(
            unicorn_value, interpreted_value,
            "{name}: location {register} mismatch\nunicorn: {:#x}\nsemantics: {:#x}",
            unicorn_value, interpreted_value
        );
    }
    for (address, size) in &interpreted.memory_writes {
        for offset in 0..*size {
            let byte_address = address + offset as u64;
            let unicorn_value = unicorn
                .transition
                .post
                .memory
                .get(&byte_address)
                .copied()
                .unwrap_or_default();
            let interpreted_value = interpreted
                .transition
                .post
                .memory
                .get(&byte_address)
                .copied()
                .unwrap_or_default();
            assert_eq!(
                unicorn_value, interpreted_value,
                "{name}: memory byte mismatch at 0x{byte_address:x}\nunicorn: {:#04x}\nsemantics: {:#04x}",
                unicorn_value, interpreted_value
            );
        }
    }
}

fn interpret_arm64_semantics(
    bytes: &[u8],
    semantics: &InstructionSemantics,
    fixture: &Arm64Fixture,
    tracked_registers: &[String],
) -> Arm64Execution {
    let mut registers = tracked_registers
        .iter()
        .map(|name| (name.clone(), 0u128))
        .collect::<BTreeMap<_, _>>();
    for (register, value) in &fixture.registers {
        registers.insert(semantic_name_for_arch_register(register), *value);
    }
    let pre_registers = tracked_registers
        .iter()
        .filter_map(|name| registers.get(name).copied().map(|value| (name.clone(), value)))
        .collect::<BTreeMap<_, _>>();
    let pre_memory = fixture_memory_map(&fixture.memory);
    let pre = Arm64CpuState {
        registers: pre_registers,
        pc: ARM64_CODE_ADDRESS,
        memory: pre_memory.clone(),
    };

    let mut temporaries = BTreeMap::<u32, u128>::new();
    let mut register_writes = Vec::<(String, u128)>::new();
    let mut memory_writes = Vec::<(u64, Vec<u8>)>::new();

    for effect in &semantics.effects {
        match effect {
            SemanticEffect::Set { dst, expression } => match dst {
                SemanticLocation::Temporary { id, bits } => {
                    temporaries.insert(
                        *id,
                        mask_to_bits(
                            eval_expression(expression, &registers, &temporaries, &pre_memory),
                            *bits,
                        ),
                    );
                }
                SemanticLocation::Register { name, bits }
                | SemanticLocation::Flag { name, bits } => {
                    register_writes.push((
                        name.clone(),
                        mask_to_bits(
                            eval_expression(expression, &registers, &temporaries, &pre_memory),
                            *bits,
                        ),
                    ));
                }
                other => panic!("unsupported arm64 conformance destination: {other:?}"),
            },
            SemanticEffect::Store {
                addr,
                expression,
                bits,
                ..
            } => {
                let address = eval_expression(addr, &registers, &temporaries, &pre_memory) as u64;
                let value = eval_expression(expression, &registers, &temporaries, &pre_memory);
                memory_writes.push((address, value_to_le_bytes(value, *bits)));
            }
            other => panic!("unsupported arm64 conformance effect: {other:?}"),
        }
    }

    for (name, value) in register_writes {
        registers.insert(name, value);
    }

    let mut post_memory = pre_memory.clone();
    let mut written_ranges = Vec::<(u64, usize)>::new();
    for (address, bytes) in memory_writes {
        if !written_ranges.contains(&(address, bytes.len())) {
            written_ranges.push((address, bytes.len()));
        }
        for (offset, byte) in bytes.into_iter().enumerate() {
            post_memory.insert(address + offset as u64, byte);
        }
    }

    let post = Arm64CpuState {
        registers,
        pc: match semantics.terminator {
            SemanticTerminator::FallThrough => ARM64_CODE_ADDRESS + bytes.len() as u64,
            SemanticTerminator::Branch {
                ref condition,
                ref true_target,
                ref false_target,
            } => {
                if eval_expression(condition, &pre.registers, &temporaries, &pre_memory) != 0 {
                    relocate_code_target(eval_expression(
                        true_target,
                        &pre.registers,
                        &temporaries,
                        &pre_memory,
                    ) as u64)
                } else {
                    relocate_code_target(eval_expression(
                        false_target,
                        &pre.registers,
                        &temporaries,
                        &pre_memory,
                    ) as u64)
                }
            }
            SemanticTerminator::Jump { ref target } => {
                relocate_code_target(eval_expression(
                    target,
                    &pre.registers,
                    &temporaries,
                    &pre_memory,
                ) as u64)
            }
            ref other => panic!("unsupported arm64 conformance terminator: {other:?}"),
        },
        memory: post_memory,
    };

    Arm64Execution {
        transition: Arm64Transition { pre, post },
        memory_writes: written_ranges,
    }
}

fn eval_expression(
    expression: &SemanticExpression,
    registers: &BTreeMap<String, u128>,
    temporaries: &BTreeMap<u32, u128>,
    memory: &BTreeMap<u64, u8>,
) -> u128 {
    match expression {
        SemanticExpression::Const { value, bits } => mask_to_bits(*value, *bits),
        SemanticExpression::Read(location) => match location.as_ref() {
            SemanticLocation::Register { name, bits }
            | SemanticLocation::Flag { name, bits } => {
                mask_to_bits(registers.get(name).copied().unwrap_or_default(), *bits)
            }
            SemanticLocation::Temporary { id, bits } => {
                mask_to_bits(temporaries.get(id).copied().unwrap_or_default(), *bits)
            }
            other => panic!("unsupported arm64 conformance read: {other:?}"),
        },
        SemanticExpression::Load { addr, bits, .. } => {
            let address = eval_expression(addr, registers, temporaries, memory) as u64;
            load_le_value(memory, address, *bits)
        }
        SemanticExpression::Binary { op, left, right, bits } => {
            let left = eval_expression(left, registers, temporaries, memory);
            let right = eval_expression(right, registers, temporaries, memory);
            let value = match op {
                SemanticOperationBinary::Add => left.wrapping_add(right),
                SemanticOperationBinary::Sub => left.wrapping_sub(right),
                SemanticOperationBinary::Mul => left.wrapping_mul(right),
                SemanticOperationBinary::FAdd => float_add_with_width(left, right, *bits),
                SemanticOperationBinary::FSub => float_sub_with_width(left, right, *bits),
                SemanticOperationBinary::FMul => float_mul_with_width(left, right, *bits),
                SemanticOperationBinary::FDiv => float_div_with_width(left, right, *bits),
                SemanticOperationBinary::UMulHigh => unsigned_mul_high_with_width(left, right, *bits),
                SemanticOperationBinary::SMulHigh => signed_mul_high_with_width(left, right, *bits),
                SemanticOperationBinary::UDiv => {
                    if right == 0 { 0 } else { left / right }
                }
                SemanticOperationBinary::SDiv => {
                    if right == 0 {
                        0
                    } else {
                        signed_div_with_width(left, right, *bits)
                    }
                }
                SemanticOperationBinary::And => left & right,
                SemanticOperationBinary::Or => left | right,
                SemanticOperationBinary::Xor => left ^ right,
                SemanticOperationBinary::Shl => left.wrapping_shl(right as u32),
                SemanticOperationBinary::LShr => left.wrapping_shr(right as u32),
                SemanticOperationBinary::AShr => {
                    let signed = sign_extend(left, *bits);
                    ((signed as i128) >> (right as u32)) as u128
                }
                SemanticOperationBinary::RotateRight => rotate_right_with_width(left, right, *bits),
                other => panic!("unsupported arm64 conformance binary op: {other:?}"),
            };
            mask_to_bits(value, *bits)
        }
        SemanticExpression::Unary { op, arg, bits } => {
            let arg = eval_expression(arg, registers, temporaries, memory);
            let value = match op {
                SemanticOperationUnary::Not => !arg,
                SemanticOperationUnary::BitReverse => bit_reverse_with_width(arg, *bits),
                SemanticOperationUnary::CountLeadingZeros => count_leading_zeros_with_width(arg, *bits),
                SemanticOperationUnary::PopCount => (mask_to_bits(arg, *bits)).count_ones() as u128,
                SemanticOperationUnary::ByteSwap => byte_swap_with_width(arg, *bits),
                other => panic!("unsupported arm64 conformance unary op: {other:?}"),
            };
            mask_to_bits(value, *bits)
        }
        SemanticExpression::Cast { op, arg, bits } => {
            let arg_value = eval_expression(arg, registers, temporaries, memory);
            let arg_bits = expression_bits(arg);
            let value = match op {
                SemanticOperationCast::ZeroExtend => arg_value,
                SemanticOperationCast::SignExtend => sign_extend(arg_value, arg_bits),
                SemanticOperationCast::FloatToInt => float_to_int_bits(arg_value, *bits),
                SemanticOperationCast::FloatToUInt => float_to_uint_bits(arg_value, *bits),
                SemanticOperationCast::IntToFloat => int_to_float_bits(arg_value, arg_bits, *bits),
                SemanticOperationCast::UIntToFloat => uint_to_float_bits(arg_value, arg_bits, *bits),
                other => panic!("unsupported arm64 conformance cast op: {other:?}"),
            };
            mask_to_bits(value, *bits)
        }
        SemanticExpression::Compare {
            op, left, right, ..
        } => {
            let compare_bits = expression_bits(left);
            let left = eval_expression(left, registers, temporaries, memory);
            let right = eval_expression(right, registers, temporaries, memory);
            match op {
                SemanticOperationCompare::Eq => (left == right) as u128,
                SemanticOperationCompare::Ne => (left != right) as u128,
                SemanticOperationCompare::Ult => (left < right) as u128,
                SemanticOperationCompare::Ule => (left <= right) as u128,
                SemanticOperationCompare::Ugt => (left > right) as u128,
                SemanticOperationCompare::Uge => (left >= right) as u128,
                SemanticOperationCompare::Slt => {
                    (compare_signed(left, right, compare_bits) == std::cmp::Ordering::Less) as u128
                }
                SemanticOperationCompare::Sle => {
                    (compare_signed(left, right, compare_bits) != std::cmp::Ordering::Greater)
                        as u128
                }
                SemanticOperationCompare::Sgt => {
                    (compare_signed(left, right, compare_bits) == std::cmp::Ordering::Greater)
                        as u128
                }
                SemanticOperationCompare::Sge => {
                    (compare_signed(left, right, compare_bits) != std::cmp::Ordering::Less) as u128
                }
                SemanticOperationCompare::Ordered => {
                    ordered_fp_compare(left, right, compare_bits, |_, _| true) as u128
                }
                SemanticOperationCompare::Unordered => {
                    unordered_fp_compare(left, right, compare_bits) as u128
                }
                SemanticOperationCompare::Oeq => {
                    ordered_fp_compare(left, right, compare_bits, |l, r| l == r) as u128
                }
                SemanticOperationCompare::Olt => {
                    ordered_fp_compare(left, right, compare_bits, |l, r| l < r) as u128
                }
                SemanticOperationCompare::Ole => {
                    ordered_fp_compare(left, right, compare_bits, |l, r| l <= r) as u128
                }
                SemanticOperationCompare::Ogt => {
                    ordered_fp_compare(left, right, compare_bits, |l, r| l > r) as u128
                }
                SemanticOperationCompare::Oge => {
                    ordered_fp_compare(left, right, compare_bits, |l, r| l >= r) as u128
                }
                other => panic!("unsupported arm64 conformance compare op: {other:?}"),
            }
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            if eval_expression(condition, registers, temporaries, memory) != 0 {
                eval_expression(when_true, registers, temporaries, memory)
            } else {
                eval_expression(when_false, registers, temporaries, memory)
            }
        }
        SemanticExpression::Extract { arg, lsb, bits } => {
            mask_to_bits(eval_expression(arg, registers, temporaries, memory) >> *lsb as u32, *bits)
        }
        SemanticExpression::Concat { parts, bits } => {
            let mut value = 0u128;
            for part in parts {
                let part_bits = expression_bits(part) as u32;
                let part_value = eval_expression(part, registers, temporaries, memory);
                value <<= part_bits;
                value |= mask_to_bits(part_value, part_bits as u16);
            }
            mask_to_bits(value, *bits)
        }
        other => panic!("unsupported arm64 conformance expression: {other:?}"),
    }
}

fn relocate_code_target(address: u64) -> u64 {
    if address < ARM64_CODE_ADDRESS {
        address + ARM64_CODE_ADDRESS
    } else {
        address
    }
}

fn tracked_registers(semantics: &InstructionSemantics, fixture: &Arm64Fixture) -> Vec<String> {
    let mut tracked = fixture
        .registers
        .iter()
        .filter(|(name, _)| !is_vector_fixture_register(name))
        .map(|(name, _)| semantic_name_for_arch_register(name))
        .collect::<Vec<_>>();
    for register in written_locations(semantics) {
        if !is_vector_semantic_register(&register) && !tracked.contains(&register) {
            tracked.push(register);
        }
    }
    tracked.sort();
    tracked
}

fn written_locations(semantics: &InstructionSemantics) -> Vec<String> {
    let mut registers = Vec::new();
    for effect in &semantics.effects {
        if let SemanticEffect::Set {
            dst: SemanticLocation::Register { name, .. } | SemanticLocation::Flag { name, .. },
            ..
        } = effect
        {
            if !registers.contains(name) {
                registers.push(name.clone());
            }
        }
    }
    registers
}

fn is_vector_fixture_register(name: &str) -> bool {
    matches!(name, "v0" | "v1" | "v2" | "q0" | "q1" | "q2")
}

fn is_vector_semantic_register(name: &str) -> bool {
    name == semantic_name_for_arch_register("v0")
        || name == semantic_name_for_arch_register("v1")
        || name == semantic_name_for_arch_register("v2")
}

fn vector_spill_address(name: &str) -> Option<u64> {
    if name == semantic_name_for_arch_register("v0") {
        Some(0x4000)
    } else if name == semantic_name_for_arch_register("v1") {
        Some(0x4010)
    } else if name == semantic_name_for_arch_register("v2") {
        Some(0x4020)
    } else {
        None
    }
}

fn fixture_memory_map(ranges: &[(u64, Vec<u8>)]) -> BTreeMap<u64, u8> {
    let mut memory = BTreeMap::new();
    for (address, bytes) in ranges {
        for (offset, byte) in bytes.iter().copied().enumerate() {
            memory.insert(address + offset as u64, byte);
        }
    }
    memory
}

fn mask_to_bits(value: u128, bits: u16) -> u128 {
    if bits >= 128 {
        value
    } else if bits == 0 {
        0
    } else {
        value & ((1u128 << bits) - 1)
    }
}

fn value_to_le_bytes(value: u128, bits: u16) -> Vec<u8> {
    let byte_len = (bits as usize).div_ceil(8);
    value.to_le_bytes()[..byte_len].to_vec()
}

fn load_le_value(memory: &BTreeMap<u64, u8>, address: u64, bits: u16) -> u128 {
    let byte_len = (bits as usize).div_ceil(8);
    let mut bytes = [0u8; 16];
    for (offset, slot) in bytes.iter_mut().take(byte_len).enumerate() {
        *slot = memory
            .get(&(address + offset as u64))
            .copied()
            .unwrap_or_default();
    }
    mask_to_bits(u128::from_le_bytes(bytes), bits)
}

fn expression_bits(expression: &SemanticExpression) -> u16 {
    match expression {
        SemanticExpression::Const { bits, .. }
        | SemanticExpression::Load { bits, .. }
        | SemanticExpression::Unary { bits, .. }
        | SemanticExpression::Binary { bits, .. }
        | SemanticExpression::Cast { bits, .. }
        | SemanticExpression::Compare { bits, .. }
        | SemanticExpression::Select { bits, .. }
        | SemanticExpression::Extract { bits, .. }
        | SemanticExpression::Concat { bits, .. } => *bits,
        SemanticExpression::Read(location) => location.bits(),
        other => panic!("unsupported arm64 conformance bit-width query: {other:?}"),
    }
}

fn sign_extend(value: u128, bits: u16) -> u128 {
    if bits == 0 || bits >= 128 {
        value
    } else {
        let shift = 128 - bits as u32;
        (((value << shift) as i128) >> shift) as u128
    }
}

fn compare_signed(left: u128, right: u128, bits: u16) -> std::cmp::Ordering {
    sign_extend(left, bits).cmp(&sign_extend(right, bits))
}

fn float_add_with_width(left: u128, right: u128, bits: u16) -> u128 {
    match bits {
        32 => (f32::from_bits(left as u32) + f32::from_bits(right as u32)).to_bits() as u128,
        64 => (f64::from_bits(left as u64) + f64::from_bits(right as u64)).to_bits() as u128,
        _ => panic!("unsupported arm64 floating add width: {bits}"),
    }
}

fn float_sub_with_width(left: u128, right: u128, bits: u16) -> u128 {
    match bits {
        32 => (f32::from_bits(left as u32) - f32::from_bits(right as u32)).to_bits() as u128,
        64 => (f64::from_bits(left as u64) - f64::from_bits(right as u64)).to_bits() as u128,
        _ => panic!("unsupported arm64 floating sub width: {bits}"),
    }
}

fn float_mul_with_width(left: u128, right: u128, bits: u16) -> u128 {
    match bits {
        32 => (f32::from_bits(left as u32) * f32::from_bits(right as u32)).to_bits() as u128,
        64 => (f64::from_bits(left as u64) * f64::from_bits(right as u64)).to_bits() as u128,
        _ => panic!("unsupported arm64 floating mul width: {bits}"),
    }
}

fn float_div_with_width(left: u128, right: u128, bits: u16) -> u128 {
    match bits {
        32 => (f32::from_bits(left as u32) / f32::from_bits(right as u32)).to_bits() as u128,
        64 => (f64::from_bits(left as u64) / f64::from_bits(right as u64)).to_bits() as u128,
        _ => panic!("unsupported arm64 floating div width: {bits}"),
    }
}

fn float_to_int_bits(value: u128, bits: u16) -> u128 {
    let float = f64::from_bits(value as u64);
    match bits {
        32 => {
            if !float.is_finite() || float < i32::MIN as f64 || float > i32::MAX as f64 {
                i32::MIN as u32 as u128
            } else {
                float.trunc() as i32 as u32 as u128
            }
        }
        64 => {
            if !float.is_finite() || float < i64::MIN as f64 || float > i64::MAX as f64 {
                i64::MIN as u64 as u128
            } else {
                float.trunc() as i64 as u64 as u128
            }
        }
        _ => panic!("unsupported arm64 float-to-int width: {bits}"),
    }
}

fn int_to_float_bits(value: u128, from_bits: u16, bits: u16) -> u128 {
    match bits {
        32 => {
            let signed = match from_bits {
                32 => (mask_to_bits(value, 32) as u32 as i32) as f32,
                64 => (mask_to_bits(value, 64) as u64 as i64) as f32,
                _ => panic!("unsupported arm64 int-to-float source width: {from_bits}"),
            };
            signed.to_bits() as u128
        }
        64 => {
            let signed = match from_bits {
                32 => (mask_to_bits(value, 32) as u32 as i32) as f64,
                64 => (mask_to_bits(value, 64) as u64 as i64) as f64,
                _ => panic!("unsupported arm64 int-to-float source width: {from_bits}"),
            };
            signed.to_bits() as u128
        }
        _ => panic!("unsupported arm64 int-to-float destination width: {bits}"),
    }
}

fn uint_to_float_bits(value: u128, from_bits: u16, bits: u16) -> u128 {
    match bits {
        32 => {
            let unsigned = match from_bits {
                32 => mask_to_bits(value, 32) as u32 as f32,
                64 => mask_to_bits(value, 64) as f32,
                _ => panic!("unsupported arm64 uint-to-float source width: {from_bits}"),
            };
            unsigned.to_bits() as u128
        }
        64 => {
            let unsigned = match from_bits {
                32 => mask_to_bits(value, 32) as u32 as f64,
                64 => mask_to_bits(value, 64) as f64,
                _ => panic!("unsupported arm64 uint-to-float source width: {from_bits}"),
            };
            unsigned.to_bits() as u128
        }
        _ => panic!("unsupported arm64 uint-to-float destination width: {bits}"),
    }
}

fn float_to_uint_bits(value: u128, bits: u16) -> u128 {
    let float = f64::from_bits(value as u64);
    match bits {
        32 => {
            if !float.is_finite() || float <= -1.0 || float > u32::MAX as f64 {
                0
            } else {
                float.trunc() as u32 as u128
            }
        }
        64 => {
            if !float.is_finite() || float <= -1.0 || float > u64::MAX as f64 {
                0
            } else {
                float.trunc() as u64 as u128
            }
        }
        _ => panic!("unsupported arm64 float-to-uint width: {bits}"),
    }
}

fn unordered_fp_compare(left: u128, right: u128, bits: u16) -> bool {
    match bits {
        32 => f32::from_bits(left as u32).is_nan() || f32::from_bits(right as u32).is_nan(),
        64 => f64::from_bits(left as u64).is_nan() || f64::from_bits(right as u64).is_nan(),
        _ => panic!("unsupported arm64 floating compare width: {bits}"),
    }
}

fn ordered_fp_compare(
    left: u128,
    right: u128,
    bits: u16,
    predicate: impl FnOnce(f64, f64) -> bool,
) -> bool {
    if unordered_fp_compare(left, right, bits) {
        false
    } else {
        match bits {
            32 => predicate(f32::from_bits(left as u32) as f64, f32::from_bits(right as u32) as f64),
            64 => predicate(f64::from_bits(left as u64), f64::from_bits(right as u64)),
            _ => panic!("unsupported arm64 floating compare width: {bits}"),
        }
    }
}

fn rotate_right_with_width(value: u128, amount: u128, bits: u16) -> u128 {
    let masked = mask_to_bits(value, bits);
    if bits == 0 {
        return 0;
    }
    let amount = (amount % bits as u128) as u32;
    if bits == 128 {
        masked.rotate_right(amount)
    } else if bits == 64 {
        (masked as u64).rotate_right(amount) as u128
    } else {
        let low = masked as u32;
        mask_to_bits(low.rotate_right(amount) as u128, bits)
    }
}

fn count_leading_zeros_with_width(value: u128, bits: u16) -> u128 {
    let masked = mask_to_bits(value, bits);
    if bits == 0 {
        return 0;
    }
    for bit in (0..bits).rev() {
        if ((masked >> bit) & 1) != 0 {
            return (bits - 1 - bit) as u128;
        }
    }
    bits as u128
}

fn byte_swap_with_width(value: u128, bits: u16) -> u128 {
    let masked = mask_to_bits(value, bits);
    match bits {
        128 => masked.swap_bytes(),
        64 => (masked as u64).swap_bytes() as u128,
        32 => (masked as u32).swap_bytes() as u128,
        16 => (masked as u16).swap_bytes() as u128,
        8 => masked,
        other => panic!("unsupported arm64 conformance byte-swap width: {other}"),
    }
}

fn bit_reverse_with_width(value: u128, bits: u16) -> u128 {
    let masked = mask_to_bits(value, bits);
    match bits {
        128 => masked.reverse_bits(),
        64 => (masked as u64).reverse_bits() as u128,
        32 => (masked as u32).reverse_bits() as u128,
        16 => (masked as u16).reverse_bits() as u128,
        8 => (masked as u8).reverse_bits() as u128,
        other => panic!("unsupported arm64 conformance bit-reverse width: {other}"),
    }
}

fn signed_div_with_width(left: u128, right: u128, bits: u16) -> u128 {
    match bits {
        64 => ((left as u64 as i64) / (right as u64 as i64)) as u64 as u128,
        32 => (((left as u32) as i32) / ((right as u32) as i32)) as u32 as u128,
        16 => (((left as u16) as i16) / ((right as u16) as i16)) as u16 as u128,
        8 => (((left as u8) as i8) / ((right as u8) as i8)) as u8 as u128,
        other => panic!("unsupported arm64 conformance signed division width: {other}"),
    }
}

fn unsigned_mul_high_with_width(left: u128, right: u128, bits: u16) -> u128 {
    match bits {
        64 => ((left * right) >> 64) as u64 as u128,
        32 => ((((left as u32 as u64) * (right as u32 as u64)) >> 32) as u32) as u128,
        other => panic!("unsupported arm64 conformance unsigned mul-high width: {other}"),
    }
}

fn signed_mul_high_with_width(left: u128, right: u128, bits: u16) -> u128 {
    match bits {
        64 => {
            let product = (left as u64 as i64 as i128) * (right as u64 as i64 as i128);
            ((product >> 64) as i64) as u64 as u128
        }
        32 => {
            let product = (left as u32 as i32 as i64) * (right as u32 as i32 as i64);
            ((product >> 32) as i32) as u32 as u128
        }
        other => panic!("unsupported arm64 conformance signed mul-high width: {other}"),
    }
}
