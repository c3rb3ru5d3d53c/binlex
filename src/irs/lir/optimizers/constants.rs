use crate::irs::lir::{
    Lir, LirEffect, LirExpression, LirFunction, LirLocation, LirModule, LirOperationBinary,
    LirOperationCast, LirOperationCompare, LirOperationUnary, LirTerminator,
};

pub fn optimize_constants(lir: &mut Lir) {
    for effect in &mut lir.effects {
        optimize_effect(effect);
    }
    optimize_terminator(&mut lir.terminator);
}

pub fn optimize_constants_function(function: &mut LirFunction) {
    for block in &mut function.blocks {
        for lir in &mut block.instructions {
            optimize_constants(lir);
        }
    }
}

pub fn optimize_constants_module(module: &mut LirModule) {
    for function in &mut module.functions {
        optimize_constants_function(function);
    }
}

fn optimize_effect(effect: &mut LirEffect) {
    match effect {
        LirEffect::Set { expression, .. }
        | LirEffect::Push { expression, .. }
        | LirEffect::Store { expression, .. } => {
            optimize_expression(expression);
        }
        LirEffect::MemorySet {
            addr,
            value,
            count,
            decrement,
            ..
        } => {
            optimize_expression(addr);
            optimize_expression(value);
            optimize_expression(count);
            optimize_expression(decrement);
        }
        LirEffect::MemoryCopy {
            src_addr,
            dst_addr,
            count,
            decrement,
            ..
        } => {
            optimize_expression(src_addr);
            optimize_expression(dst_addr);
            optimize_expression(count);
            optimize_expression(decrement);
        }
        LirEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            ..
        } => {
            optimize_expression(addr);
            optimize_expression(expected);
            optimize_expression(desired);
        }
        LirEffect::WriteProperty {
            reference,
            expression,
            ..
        } => {
            optimize_expression(reference);
            optimize_expression(expression);
        }
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            ..
        } => {
            optimize_expression(reference);
            optimize_expression(index);
            optimize_expression(expression);
        }
        LirEffect::Intrinsic { args, .. } => {
            for arg in args {
                optimize_expression(arg);
            }
        }
        LirEffect::Pop { .. }
        | LirEffect::Fence { .. }
        | LirEffect::Trap { .. }
        | LirEffect::Nop => {}
    }
}

fn optimize_terminator(terminator: &mut LirTerminator) {
    match terminator {
        LirTerminator::Jump { target } => optimize_expression(target),
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            optimize_expression(condition);
            optimize_expression(true_target);
            optimize_expression(false_target);
        }
        LirTerminator::Call {
            target,
            return_target,
            ..
        } => {
            optimize_expression(target);
            if let Some(return_target) = return_target {
                optimize_expression(return_target);
            }
        }
        LirTerminator::Return { expression } => {
            if let Some(expression) = expression {
                optimize_expression(expression);
            }
        }
        LirTerminator::FallThrough | LirTerminator::Unreachable | LirTerminator::Trap => {}
    }
}

fn optimize_expression(expression: &mut LirExpression) {
    match expression {
        LirExpression::AddressOf { location, .. } | LirExpression::Read(location) => {
            optimize_location(location);
        }
        LirExpression::Load { addr, .. } => optimize_expression(addr),
        LirExpression::Unary { op, arg, bits } => {
            optimize_expression(arg);
            if let Some(result) = fold_unary(*op, arg, *bits) {
                *expression = result;
            }
        }
        LirExpression::Binary {
            op,
            left,
            right,
            bits,
        } => {
            optimize_expression(left);
            optimize_expression(right);
            if let Some(result) = fold_binary(*op, left, right, *bits) {
                *expression = result;
            }
        }
        LirExpression::Cast { op, arg, bits } => {
            optimize_expression(arg);
            if let Some(result) = fold_cast(*op, arg, *bits) {
                *expression = result;
            }
        }
        LirExpression::Compare {
            op,
            left,
            right,
            bits,
        } => {
            optimize_expression(left);
            optimize_expression(right);
            if let Some(result) = fold_compare(*op, left, right, *bits) {
                *expression = result;
            }
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            optimize_expression(condition);
            optimize_expression(when_true);
            optimize_expression(when_false);
            if let Some(result) = fold_select(condition, when_true, when_false) {
                *expression = result;
            }
        }
        LirExpression::Extract { arg, lsb, bits } => {
            optimize_expression(arg);
            if let Some(result) = fold_extract(arg, *lsb, *bits) {
                *expression = result;
            }
        }
        LirExpression::Concat { parts, bits } => {
            for part in parts.iter_mut() {
                optimize_expression(part);
            }
            if let Some(result) = fold_concat(parts, *bits) {
                *expression = result;
            }
        }
        LirExpression::Intrinsic { args, .. } => {
            for arg in args {
                optimize_expression(arg);
            }
        }
        LirExpression::ReadProperty { reference, .. } => optimize_expression(reference),
        LirExpression::ReadElement {
            reference, index, ..
        } => {
            optimize_expression(reference);
            optimize_expression(index);
        }
        LirExpression::Const { .. }
        | LirExpression::Function { .. }
        | LirExpression::DataAddress { .. }
        | LirExpression::Undefined { .. }
        | LirExpression::Poison { .. }
        | LirExpression::Null { .. }
        | LirExpression::Allocate { .. } => {}
    }
}

fn optimize_location(location: &mut LirLocation) {
    match location {
        LirLocation::Memory { addr, .. } | LirLocation::IndexedMemory { index: addr, .. } => {
            optimize_expression(addr);
        }
        LirLocation::Register { .. }
        | LirLocation::Flag { .. }
        | LirLocation::ProgramCounter { .. }
        | LirLocation::Temporary { .. }
        | LirLocation::StackMemory { .. } => {}
    }
}

fn const_value(expression: &LirExpression) -> Option<(u128, u16)> {
    match expression {
        LirExpression::Const { value, bits } => Some((*value, *bits)),
        LirExpression::Null { bits } => Some((0, *bits)),
        _ => None,
    }
}

fn bool_like(value: u128) -> bool {
    value != 0
}

fn fold_unary(op: LirOperationUnary, arg: &LirExpression, bits: u16) -> Option<LirExpression> {
    let (value, _) = const_value(arg)?;
    let mask = bit_mask(bits);
    let folded = match op {
        LirOperationUnary::Not => (!value) & mask,
        LirOperationUnary::Neg => value.wrapping_neg() & mask,
        LirOperationUnary::BitReverse => reverse_bits(value, bits),
        LirOperationUnary::ByteSwap => byte_swap(value, bits),
        LirOperationUnary::CountLeadingZeros => leading_zeros(value, bits) as u128,
        LirOperationUnary::CountTrailingZeros => trailing_zeros(value, bits) as u128,
        LirOperationUnary::PopCount => value.count_ones() as u128,
        LirOperationUnary::Abs | LirOperationUnary::Sqrt => return None,
    };
    Some(LirExpression::Const {
        value: folded,
        bits,
    })
}

fn fold_binary(
    op: LirOperationBinary,
    left: &LirExpression,
    right: &LirExpression,
    bits: u16,
) -> Option<LirExpression> {
    let (lhs, _) = const_value(left)?;
    let (rhs, _) = const_value(right)?;
    let mask = bit_mask(bits);
    let folded = match op {
        LirOperationBinary::Add => lhs.wrapping_add(rhs) & mask,
        LirOperationBinary::Sub => lhs.wrapping_sub(rhs) & mask,
        LirOperationBinary::Mul => lhs.wrapping_mul(rhs) & mask,
        LirOperationBinary::UDiv => {
            if rhs == 0 {
                return None;
            }
            lhs / rhs
        }
        LirOperationBinary::URem => {
            if rhs == 0 {
                return None;
            }
            lhs % rhs
        }
        LirOperationBinary::And => lhs & rhs,
        LirOperationBinary::Or => lhs | rhs,
        LirOperationBinary::Xor => lhs ^ rhs,
        LirOperationBinary::Shl => lhs.wrapping_shl(rhs as u32) & mask,
        LirOperationBinary::LShr => lhs.wrapping_shr(rhs as u32),
        LirOperationBinary::RotateLeft => rotate_left(lhs, rhs as u32, bits),
        LirOperationBinary::RotateRight => rotate_right(lhs, rhs as u32, bits),
        LirOperationBinary::MinUnsigned => lhs.min(rhs),
        LirOperationBinary::MaxUnsigned => lhs.max(rhs),
        LirOperationBinary::AddWithCarry
        | LirOperationBinary::SubWithBorrow
        | LirOperationBinary::FAdd
        | LirOperationBinary::FSub
        | LirOperationBinary::FMul
        | LirOperationBinary::FDiv
        | LirOperationBinary::UMulHigh
        | LirOperationBinary::SMulHigh
        | LirOperationBinary::SDiv
        | LirOperationBinary::SRem
        | LirOperationBinary::AShr
        | LirOperationBinary::MinSigned
        | LirOperationBinary::MaxSigned => return None,
    };
    Some(LirExpression::Const {
        value: folded,
        bits,
    })
}

fn fold_cast(op: LirOperationCast, arg: &LirExpression, bits: u16) -> Option<LirExpression> {
    let (value, _) = const_value(arg)?;
    let folded = match op {
        LirOperationCast::ZeroExtend | LirOperationCast::Bitcast => value & bit_mask(bits),
        LirOperationCast::Truncate => value & bit_mask(bits),
        LirOperationCast::SignExtend => sign_extend(value, arg.bits(), bits),
        LirOperationCast::IntToFloat
        | LirOperationCast::UIntToFloat
        | LirOperationCast::FloatToInt
        | LirOperationCast::FloatToUInt
        | LirOperationCast::FloatExtend
        | LirOperationCast::FloatTruncate => return None,
    };
    Some(LirExpression::Const {
        value: folded,
        bits,
    })
}

fn fold_compare(
    op: LirOperationCompare,
    left: &LirExpression,
    right: &LirExpression,
    bits: u16,
) -> Option<LirExpression> {
    let (lhs, left_bits) = const_value(left)?;
    let (rhs, right_bits) = const_value(right)?;
    let result = match op {
        LirOperationCompare::Eq => lhs == rhs,
        LirOperationCompare::Ne => lhs != rhs,
        LirOperationCompare::Ult => lhs < rhs,
        LirOperationCompare::Ule => lhs <= rhs,
        LirOperationCompare::Ugt => lhs > rhs,
        LirOperationCompare::Uge => lhs >= rhs,
        LirOperationCompare::Slt => signed_value(lhs, left_bits) < signed_value(rhs, right_bits),
        LirOperationCompare::Sle => signed_value(lhs, left_bits) <= signed_value(rhs, right_bits),
        LirOperationCompare::Sgt => signed_value(lhs, left_bits) > signed_value(rhs, right_bits),
        LirOperationCompare::Sge => signed_value(lhs, left_bits) >= signed_value(rhs, right_bits),
        LirOperationCompare::Ordered
        | LirOperationCompare::Unordered
        | LirOperationCompare::Oeq
        | LirOperationCompare::One
        | LirOperationCompare::Olt
        | LirOperationCompare::Ole
        | LirOperationCompare::Ogt
        | LirOperationCompare::Oge
        | LirOperationCompare::Ueq
        | LirOperationCompare::Une
        | LirOperationCompare::UltFp
        | LirOperationCompare::UleFp
        | LirOperationCompare::UgtFp
        | LirOperationCompare::UgeFp => return None,
    };
    Some(LirExpression::Const {
        value: u128::from(result),
        bits,
    })
}

fn fold_select(
    condition: &LirExpression,
    when_true: &LirExpression,
    when_false: &LirExpression,
) -> Option<LirExpression> {
    let (value, _) = const_value(condition)?;
    if bool_like(value) {
        Some(when_true.clone())
    } else {
        Some(when_false.clone())
    }
}

fn fold_extract(arg: &LirExpression, lsb: u16, bits: u16) -> Option<LirExpression> {
    let (value, _) = const_value(arg)?;
    Some(LirExpression::Const {
        value: (value >> lsb) & bit_mask(bits),
        bits,
    })
}

fn fold_concat(parts: &[LirExpression], bits: u16) -> Option<LirExpression> {
    let mut combined = 0u128;
    for part in parts {
        let (value, part_bits) = const_value(part)?;
        combined = (combined << part_bits) | (value & bit_mask(part_bits));
    }
    Some(LirExpression::Const {
        value: combined & bit_mask(bits),
        bits,
    })
}

fn bit_mask(bits: u16) -> u128 {
    match bits {
        0 => 0,
        128.. => u128::MAX,
        _ => (1u128 << bits) - 1,
    }
}

fn signed_value(value: u128, bits: u16) -> i128 {
    if bits == 0 {
        return 0;
    }
    if bits >= 128 {
        return value as i128;
    }
    let sign_bit = 1u128 << (bits - 1);
    let masked = value & bit_mask(bits);
    if masked & sign_bit == 0 {
        masked as i128
    } else {
        (masked as i128) - ((1u128 << bits) as i128)
    }
}

fn sign_extend(value: u128, from_bits: u16, to_bits: u16) -> u128 {
    if to_bits >= 128 {
        return signed_value(value, from_bits) as u128;
    }
    let signed = signed_value(value, from_bits);
    (signed as u128) & bit_mask(to_bits)
}

fn reverse_bits(value: u128, bits: u16) -> u128 {
    value.reverse_bits() >> (128 - bits.min(128))
}

fn byte_swap(value: u128, bits: u16) -> u128 {
    match bits {
        8 => value & 0xff,
        16 => (value as u16).swap_bytes() as u128,
        32 => (value as u32).swap_bytes() as u128,
        64 => (value as u64).swap_bytes() as u128,
        128 => value.swap_bytes(),
        _ => value,
    }
}

fn leading_zeros(value: u128, bits: u16) -> u16 {
    let width = bits.min(128);
    if width == 0 {
        return 0;
    }
    let masked = value & bit_mask(width);
    if masked == 0 {
        return width;
    }
    (masked.leading_zeros() as u16).saturating_sub(128 - width)
}

fn trailing_zeros(value: u128, bits: u16) -> u16 {
    let width = bits.min(128);
    if width == 0 {
        return 0;
    }
    let masked = value & bit_mask(width);
    if masked == 0 {
        return width;
    }
    masked.trailing_zeros() as u16
}

fn rotate_left(value: u128, amount: u32, bits: u16) -> u128 {
    let width = bits.min(128) as u32;
    if width == 0 {
        return value;
    }
    let amount = amount % width;
    let value = value & bit_mask(bits);
    ((value << amount) | (value >> (width - amount))) & bit_mask(bits)
}

fn rotate_right(value: u128, amount: u32, bits: u16) -> u128 {
    let width = bits.min(128) as u32;
    if width == 0 {
        return value;
    }
    let amount = amount % width;
    let value = value & bit_mask(bits);
    ((value >> amount) | (value << (width - amount))) & bit_mask(bits)
}
