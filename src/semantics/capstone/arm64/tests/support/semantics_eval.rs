use std::collections::BTreeMap;

use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticOperationUnary, SemanticTerminator,
};

use super::common::semantics;
use super::fixtures::{Arm64CpuState, Arm64Execution, Arm64Fixture, Arm64Transition};
use super::unicorn::{
    ARM64_CODE_ADDRESS, semantic_name_for_arch_register, unicorn_arm64_execution,
};

pub(crate) fn assert_arm64_semantics_match_unicorn(
    name: &str,
    bytes: &[u8],
    fixture: Arm64Fixture,
) {
    let semantics = semantics(name, bytes);
    let tracked_registers = tracked_registers(&semantics, &fixture);
    let vector_register_writes = written_locations(&semantics)
        .into_iter()
        .filter(|name| is_vector_semantic_register(name))
        .collect::<Vec<_>>();
    let interpreted =
        interpret_arm64_semantics(name, bytes, &semantics, &fixture, &tracked_registers);
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
    instruction_name: &str,
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
        .filter_map(|name| {
            registers
                .get(name)
                .copied()
                .map(|value| (name.clone(), value))
        })
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
            SemanticEffect::Nop => {}
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
                SemanticLocation::Register {
                    name: dst_name,
                    bits,
                }
                | SemanticLocation::Flag {
                    name: dst_name,
                    bits,
                } => {
                    let value = mask_to_bits(
                        eval_expression(expression, &registers, &temporaries, &pre_memory),
                        *bits,
                    );
                    register_writes.push((
                        dst_name.clone(),
                        relocate_adr_like_result(instruction_name, value, expression),
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
            SemanticEffect::AtomicCmpXchg {
                addr,
                expected,
                desired,
                bits,
                observed,
                ..
            } => {
                let address = eval_expression(addr, &registers, &temporaries, &pre_memory) as u64;
                let current = load_le_value(&pre_memory, address, *bits);
                let expected_value = mask_to_bits(
                    eval_expression(expected, &registers, &temporaries, &pre_memory),
                    *bits,
                );
                let desired_value = mask_to_bits(
                    eval_expression(desired, &registers, &temporaries, &pre_memory),
                    *bits,
                );
                match observed {
                    SemanticLocation::Temporary { id, bits } => {
                        temporaries.insert(*id, mask_to_bits(current, *bits));
                    }
                    SemanticLocation::Register {
                        name: dst_name,
                        bits,
                    }
                    | SemanticLocation::Flag {
                        name: dst_name,
                        bits,
                    } => {
                        register_writes.push((dst_name.clone(), mask_to_bits(current, *bits)));
                    }
                    other => panic!("unsupported arm64 conformance cmpxchg destination: {other:?}"),
                }
                if current == expected_value {
                    memory_writes.push((address, value_to_le_bytes(desired_value, *bits)));
                }
            }
            SemanticEffect::Intrinsic {
                name,
                args,
                outputs,
            } => {
                let values =
                    eval_intrinsic_effect(name, args, &registers, &temporaries, &pre_memory);
                assert_eq!(
                    values.len(),
                    outputs.len(),
                    "{instruction_name}: intrinsic output arity mismatch for {name}"
                );
                for (dst, value) in outputs.iter().zip(values) {
                    match dst {
                        SemanticLocation::Register {
                            name: dst_name,
                            bits,
                        }
                        | SemanticLocation::Flag {
                            name: dst_name,
                            bits,
                        } => {
                            register_writes.push((dst_name.clone(), mask_to_bits(value, *bits)));
                        }
                        other => {
                            panic!("unsupported arm64 conformance intrinsic destination: {other:?}")
                        }
                    }
                }
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

    let post =
        Arm64CpuState {
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
                SemanticTerminator::Jump { ref target } => relocate_code_target(eval_expression(
                    target,
                    &pre.registers,
                    &temporaries,
                    &pre_memory,
                )
                    as u64),
                SemanticTerminator::Call { ref target, .. } => relocate_code_target(
                    eval_expression(target, &pre.registers, &temporaries, &pre_memory) as u64,
                ),
                SemanticTerminator::Return { ref expression } => expression
                    .as_ref()
                    .map(|expression| {
                        eval_expression(expression, &pre.registers, &temporaries, &pre_memory)
                            as u64
                    })
                    .unwrap_or_else(|| {
                        pre.registers
                            .get(&semantic_name_for_arch_register("x30"))
                            .copied()
                            .unwrap_or_default() as u64
                    }),
                ref other => panic!("unsupported arm64 conformance terminator: {other:?}"),
            },
            memory: post_memory,
        };

    Arm64Execution {
        transition: Arm64Transition { pre, post },
        memory_writes: written_ranges,
    }
}

fn relocate_adr_like_result(
    instruction_name: &str,
    value: u128,
    expression: &SemanticExpression,
) -> u128 {
    if !matches!(expression, SemanticExpression::Const { .. }) {
        return value;
    }
    if instruction_name.starts_with("adr ") || instruction_name.starts_with("adrp ") {
        return relocate_code_target(value as u64) as u128;
    }
    value
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
            SemanticLocation::Register { name, bits } | SemanticLocation::Flag { name, bits } => {
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
        SemanticExpression::Binary {
            op,
            left,
            right,
            bits,
        } => {
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
                SemanticOperationBinary::UMulHigh => {
                    unsigned_mul_high_with_width(left, right, *bits)
                }
                SemanticOperationBinary::SMulHigh => signed_mul_high_with_width(left, right, *bits),
                SemanticOperationBinary::UDiv => {
                    if right == 0 {
                        0
                    } else {
                        left / right
                    }
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
                SemanticOperationUnary::Abs => float_abs_with_width(arg, *bits),
                SemanticOperationUnary::Neg => float_neg_with_width(arg, *bits),
                SemanticOperationUnary::BitReverse => bit_reverse_with_width(arg, *bits),
                SemanticOperationUnary::CountLeadingZeros => {
                    count_leading_zeros_with_width(arg, *bits)
                }
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
                SemanticOperationCast::UIntToFloat => {
                    uint_to_float_bits(arg_value, arg_bits, *bits)
                }
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
        SemanticExpression::Extract { arg, lsb, bits } => mask_to_bits(
            eval_expression(arg, registers, temporaries, memory) >> *lsb as u32,
            *bits,
        ),
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

fn eval_intrinsic_effect(
    name: &str,
    args: &[SemanticExpression],
    registers: &BTreeMap<String, u128>,
    temporaries: &BTreeMap<u32, u128>,
    memory: &BTreeMap<u64, u8>,
) -> Vec<u128> {
    let values = args
        .iter()
        .map(|arg| eval_expression(arg, registers, temporaries, memory))
        .collect::<Vec<_>>();
    match name {
        "arm64.aese" => {
            let [state, round_key] = values.as_slice() else {
                panic!("arm64.aese: expected 2 arguments, got {}", values.len());
            };
            vec![aes_sub_bytes(aes_shift_rows(state ^ round_key))]
        }
        "arm64.aesd" => {
            let [state, round_key] = values.as_slice() else {
                panic!("arm64.aesd: expected 2 arguments, got {}", values.len());
            };
            vec![aes_inv_sub_bytes(aes_inv_shift_rows(state ^ round_key))]
        }
        "arm64.aesmc" => {
            let [state] = values.as_slice() else {
                panic!("arm64.aesmc: expected 1 argument, got {}", values.len());
            };
            vec![aes_mix_columns(*state)]
        }
        "arm64.aesimc" => {
            let [state] = values.as_slice() else {
                panic!("arm64.aesimc: expected 1 argument, got {}", values.len());
            };
            vec![aes_inv_mix_columns(*state)]
        }
        "arm64.ext" => {
            let [_, left, right, immediate] = values.as_slice() else {
                panic!("arm64.ext: expected 4 arguments, got {}", values.len());
            };
            vec![ext_vec_16b(*left, *right, *immediate as usize)]
        }
        "arm64.umov" => {
            let [_, src] = values.as_slice() else {
                panic!("arm64.umov: expected 2 arguments, got {}", values.len());
            };
            vec![*src]
        }
        name if matches!(
            name,
            "arm64.stlxr"
                | "arm64.stlxrb"
                | "arm64.stlxrh"
                | "arm64.stxr"
                | "arm64.stxrb"
                | "arm64.stxrh"
                | "arm64.stxp"
                | "arm64.stlxp"
        ) =>
        {
            vec![1]
        }
        name if name.ends_with(".monitor") => Vec::new(),
        "arm64.bfcvt" => {
            let [_dst, src] = values.as_slice() else {
                panic!("arm64.bfcvt: expected 2 arguments, got {}", values.len());
            };
            vec![bf16_from_f32_bits(*src as u32) as u128]
        }
        "arm64.bfcvtn" => {
            let [_dst, src] = values.as_slice() else {
                panic!("arm64.bfcvtn: expected 2 arguments, got {}", values.len());
            };
            vec![bfcvtn_from_v4s(*src, 0)]
        }
        "arm64.bfcvtn2" => {
            let [dst, src] = values.as_slice() else {
                panic!("arm64.bfcvtn2: expected 2 arguments, got {}", values.len());
            };
            vec![bfcvtn_from_v4s(*src, *dst)]
        }
        "arm64.bfdot" => {
            let [dst, src1, src2] = values.as_slice() else {
                panic!("arm64.bfdot: expected 3 arguments, got {}", values.len());
            };
            vec![bfdot_vec(*dst, *src1, *src2)]
        }
        "arm64.bfmlalb" => {
            let [dst, src1, src2] = values.as_slice() else {
                panic!("arm64.bfmlalb: expected 3 arguments, got {}", values.len());
            };
            vec![bfmlalb_vec(*dst, *src1, *src2)]
        }
        other => panic!("unsupported arm64 conformance intrinsic effect: {other}"),
    }
}

fn relocate_code_target(address: u64) -> u64 {
    if address < ARM64_CODE_ADDRESS {
        address + ARM64_CODE_ADDRESS
    } else {
        address
    }
}

fn ext_vec_16b(left: u128, right: u128, immediate: usize) -> u128 {
    let left_bytes = left.to_le_bytes();
    let right_bytes = right.to_le_bytes();
    let mut concatenated = [0u8; 32];
    concatenated[..16].copy_from_slice(&left_bytes);
    concatenated[16..].copy_from_slice(&right_bytes);
    let mut result = [0u8; 16];
    result.copy_from_slice(&concatenated[immediate..immediate + 16]);
    u128::from_le_bytes(result)
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
        match effect {
            SemanticEffect::Set {
                dst: SemanticLocation::Register { name, .. } | SemanticLocation::Flag { name, .. },
                ..
            } => {
                if !registers.contains(name) {
                    registers.push(name.clone());
                }
            }
            SemanticEffect::Intrinsic { outputs, .. } => {
                for output in outputs {
                    if let SemanticLocation::Register { name, .. }
                    | SemanticLocation::Flag { name, .. } = output
                    {
                        if !registers.contains(name) {
                            registers.push(name.clone());
                        }
                    }
                }
            }
            SemanticEffect::AtomicCmpXchg { observed, .. } => {
                if let SemanticLocation::Register { name, .. }
                | SemanticLocation::Flag { name, .. } = observed
                {
                    if !registers.contains(name) {
                        registers.push(name.clone());
                    }
                }
            }
            _ => {}
        }
    }
    registers
}

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

fn aes_shift_rows(state: u128) -> u128 {
    let src = state.to_le_bytes();
    let dst = [
        src[0], src[5], src[10], src[15], src[4], src[9], src[14], src[3], src[8], src[13], src[2],
        src[7], src[12], src[1], src[6], src[11],
    ];
    u128::from_le_bytes(dst)
}

fn aes_inv_shift_rows(state: u128) -> u128 {
    let src = state.to_le_bytes();
    let dst = [
        src[0], src[13], src[10], src[7], src[4], src[1], src[14], src[11], src[8], src[5], src[2],
        src[15], src[12], src[9], src[6], src[3],
    ];
    u128::from_le_bytes(dst)
}

fn aes_sub_bytes(state: u128) -> u128 {
    let mut bytes = state.to_le_bytes();
    for byte in &mut bytes {
        *byte = AES_SBOX[*byte as usize];
    }
    u128::from_le_bytes(bytes)
}

fn aes_inv_sub_bytes(state: u128) -> u128 {
    let mut bytes = state.to_le_bytes();
    for byte in &mut bytes {
        *byte = AES_INV_SBOX[*byte as usize];
    }
    u128::from_le_bytes(bytes)
}

fn aes_mix_columns(state: u128) -> u128 {
    let mut bytes = state.to_le_bytes();
    for column in bytes.chunks_exact_mut(4) {
        let [a0, a1, a2, a3] = [column[0], column[1], column[2], column[3]];
        column[0] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        column[1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        column[2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        column[3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
    u128::from_le_bytes(bytes)
}

fn aes_inv_mix_columns(state: u128) -> u128 {
    let mut bytes = state.to_le_bytes();
    for column in bytes.chunks_exact_mut(4) {
        let [a0, a1, a2, a3] = [column[0], column[1], column[2], column[3]];
        column[0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        column[1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        column[2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        column[3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
    u128::from_le_bytes(bytes)
}

fn gf_mul(mut value: u8, mut factor: u8) -> u8 {
    let mut result = 0u8;
    while factor != 0 {
        if factor & 1 != 0 {
            result ^= value;
        }
        let high_bit = value & 0x80;
        value <<= 1;
        if high_bit != 0 {
            value ^= 0x1b;
        }
        factor >>= 1;
    }
    result
}

fn bf16_to_f32_bits(bits: u16) -> u32 {
    (bits as u32) << 16
}

fn bf16_from_f32_bits(bits: u32) -> u16 {
    let rounding_bias = 0x7fffu32 + ((bits >> 16) & 1);
    ((bits.wrapping_add(rounding_bias)) >> 16) as u16
}

fn bfcvtn_from_v4s(src: u128, preserved_dst: u128) -> u128 {
    let mut result = preserved_dst;
    for lane in 0..4 {
        let src_bits = ((src >> (lane * 32)) & 0xffff_ffff) as u32;
        let bf16 = bf16_from_f32_bits(src_bits) as u128;
        let shift = lane * 16;
        result &= !(0xffffu128 << shift);
        result |= bf16 << shift;
    }
    result
}

fn bfdot_vec(dst: u128, src1: u128, src2: u128) -> u128 {
    let mut result = dst;
    for lane in 0..4 {
        let mut acc = f32::from_bits(((dst >> (lane * 32)) & 0xffff_ffff) as u32);
        let a0 = f32::from_bits(bf16_to_f32_bits(
            ((src1 >> ((2 * lane) * 16)) & 0xffff) as u16,
        ));
        let a1 = f32::from_bits(bf16_to_f32_bits(
            ((src1 >> ((2 * lane + 1) * 16)) & 0xffff) as u16,
        ));
        let b0 = f32::from_bits(bf16_to_f32_bits(
            ((src2 >> ((2 * lane) * 16)) & 0xffff) as u16,
        ));
        let b1 = f32::from_bits(bf16_to_f32_bits(
            ((src2 >> ((2 * lane + 1) * 16)) & 0xffff) as u16,
        ));
        acc += a0 * b0 + a1 * b1;
        result &= !(0xffff_ffffu128 << (lane * 32));
        result |= (acc.to_bits() as u128) << (lane * 32);
    }
    result
}

fn bfmlalb_vec(dst: u128, src1: u128, src2: u128) -> u128 {
    let mut result = dst;
    for lane in 0..4 {
        let mut acc = f32::from_bits(((dst >> (lane * 32)) & 0xffff_ffff) as u32);
        let a = f32::from_bits(bf16_to_f32_bits(
            ((src1 >> ((2 * lane) * 16)) & 0xffff) as u16,
        ));
        let b = f32::from_bits(bf16_to_f32_bits(
            ((src2 >> ((2 * lane) * 16)) & 0xffff) as u16,
        ));
        acc += a * b;
        result &= !(0xffff_ffffu128 << (lane * 32));
        result |= (acc.to_bits() as u128) << (lane * 32);
    }
    result
}

fn is_vector_fixture_register(name: &str) -> bool {
    matches!(name, "v0" | "v1" | "v2" | "v3" | "q0" | "q1" | "q2" | "q3")
}

fn is_vector_semantic_register(name: &str) -> bool {
    name == semantic_name_for_arch_register("v0")
        || name == semantic_name_for_arch_register("v1")
        || name == semantic_name_for_arch_register("v2")
        || name == semantic_name_for_arch_register("v3")
}

fn vector_spill_address(name: &str) -> Option<u64> {
    if name == semantic_name_for_arch_register("v0") {
        Some(0x4000)
    } else if name == semantic_name_for_arch_register("v1") {
        Some(0x4010)
    } else if name == semantic_name_for_arch_register("v2") {
        Some(0x4020)
    } else if name == semantic_name_for_arch_register("v3") {
        Some(0x4030)
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

fn float_abs_with_width(value: u128, bits: u16) -> u128 {
    match bits {
        32 => f32::from_bits(value as u32).abs().to_bits() as u128,
        64 => f64::from_bits(value as u64).abs().to_bits() as u128,
        _ => panic!("unsupported arm64 floating abs width: {bits}"),
    }
}

fn float_neg_with_width(value: u128, bits: u16) -> u128 {
    match bits {
        32 => (-f32::from_bits(value as u32)).to_bits() as u128,
        64 => (-f64::from_bits(value as u64)).to_bits() as u128,
        _ => panic!("unsupported arm64 floating neg width: {bits}"),
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
            32 => predicate(
                f32::from_bits(left as u32) as f64,
                f32::from_bits(right as u32) as f64,
            ),
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
