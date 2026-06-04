use crate::irs::mir::analysis::{mir_predecessors, reverse_post_order};
use crate::irs::mir::{
    Mir, MirCastOperation, MirCompareOperation, MirOperationKind, MirTerminator, MirValue,
};
use std::collections::HashMap;

type ConstantMap = HashMap<String, MirValue>;

pub fn optimize_constants(mir: &mut Mir) {
    let predecessors = mir_predecessors(mir);
    let order = reverse_post_order(mir);
    let indices = mir
        .blocks()
        .iter()
        .enumerate()
        .map(|(index, block)| (block.name.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut outgoing = HashMap::<String, ConstantMap>::new();
    let mut changed = true;

    while changed {
        changed = false;

        for block_name in &order {
            let Some(index) = indices.get(block_name).copied() else {
                continue;
            };
            let block = &mut mir.blocks_mut()[index];
            let mut constants = incoming_constants(&block.name, &predecessors, &outgoing);

            for operation in &mut block.operations {
                rewrite_operation(operation, &constants);

                if let Some(result) = operation.result.as_ref() {
                    if let Some(value) = fold_operation(&operation.kind) {
                        constants.insert(result.clone(), value);
                    } else {
                        constants.remove(result);
                    }
                }
            }

            if let Some(terminator) = block.terminator.as_mut() {
                rewrite_terminator(terminator, &constants);
            }

            if outgoing.get(&block.name) != Some(&constants) {
                outgoing.insert(block.name.clone(), constants);
                changed = true;
            }
        }
    }
}

fn incoming_constants(
    block: &str,
    predecessors: &HashMap<String, Vec<String>>,
    outgoing: &HashMap<String, ConstantMap>,
) -> ConstantMap {
    let Some(preds) = predecessors.get(block) else {
        return ConstantMap::new();
    };
    let Some((first, rest)) = preds.split_first() else {
        return ConstantMap::new();
    };
    let Some(first_constants) = outgoing.get(first) else {
        return ConstantMap::new();
    };

    let mut shared = first_constants.clone();
    for predecessor in rest {
        let Some(constants) = outgoing.get(predecessor) else {
            shared.clear();
            break;
        };
        shared.retain(|name, value| constants.get(name) == Some(value));
    }
    shared
}

fn rewrite_operation(operation: &mut crate::irs::mir::MirOperation, constants: &ConstantMap) {
    match &mut operation.kind {
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::FAdd { lhs, rhs, .. }
        | MirOperationKind::FSub { lhs, rhs, .. }
        | MirOperationKind::FMul { lhs, rhs, .. }
        | MirOperationKind::FDiv { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::UDiv { lhs, rhs, .. }
        | MirOperationKind::SDiv { lhs, rhs, .. }
        | MirOperationKind::URem { lhs, rhs, .. }
        | MirOperationKind::SRem { lhs, rhs, .. }
        | MirOperationKind::RotateLeft { lhs, rhs, .. }
        | MirOperationKind::RotateRight { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. }
        | MirOperationKind::Fcmp { lhs, rhs, .. } => {
            rewrite_value(lhs, constants);
            rewrite_value(rhs, constants);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                rewrite_value(part, constants);
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_value(condition, constants);
            rewrite_value(when_true, constants);
            rewrite_value(when_false, constants);
        }
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. } => rewrite_value(value, constants),
        MirOperationKind::Load { address, .. } | MirOperationKind::AddressOf { address, .. } => {
            rewrite_value(address, constants);
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, constants);
            rewrite_value(value, constants);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_value(src_address, constants);
            rewrite_value(dst_address, constants);
            rewrite_value(count, constants);
            rewrite_value(decrement, constants);
        }
        MirOperationKind::Cast { value, .. } => {
            rewrite_value(value, constants);
        }
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, constants);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, constants: &ConstantMap) {
    match terminator {
        MirTerminator::Jump { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, constants);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            rewrite_value(condition, constants);
            for argument in then_arguments {
                rewrite_value(argument, constants);
            }
            for argument in else_arguments {
                rewrite_value(argument, constants);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_value(value, constants);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_value(value: &mut MirValue, constants: &ConstantMap) {
    if let MirValue::Named { name, .. } = value {
        if let Some(replacement) = constants.get(name) {
            *value = replacement.clone();
        }
    }
}

fn fold_operation(kind: &MirOperationKind) -> Option<MirValue> {
    match kind {
        MirOperationKind::Copy { value, .. } => Some(value.clone()),
        MirOperationKind::Add { lhs, rhs, .. } => fold_integer_binary(lhs, rhs, |a, b| a + b),
        MirOperationKind::Sub { lhs, rhs, .. } => fold_integer_binary(lhs, rhs, |a, b| a - b),
        MirOperationKind::Mul { lhs, rhs, .. } => fold_integer_binary(lhs, rhs, |a, b| a * b),
        MirOperationKind::And { lhs, rhs, .. } => fold_integer_binary(lhs, rhs, |a, b| a & b),
        MirOperationKind::Or { lhs, rhs, .. } => fold_integer_binary(lhs, rhs, |a, b| a | b),
        MirOperationKind::Xor { lhs, rhs, .. } => fold_integer_binary(lhs, rhs, |a, b| a ^ b),
        MirOperationKind::Shl { lhs, rhs, .. } => {
            fold_integer_binary(lhs, rhs, |a, b| a.wrapping_shl(b as u32))
        }
        MirOperationKind::LShr { lhs, rhs, .. } => {
            fold_integer_binary(lhs, rhs, |a, b| ((a as u128) >> (b as u32)) as i128)
        }
        MirOperationKind::AShr { lhs, rhs, .. } => {
            fold_integer_binary(lhs, rhs, |a, b| a >> (b as u32))
        }
        MirOperationKind::UDiv { lhs, rhs, .. } => fold_unsigned_div(lhs, rhs),
        MirOperationKind::SDiv { lhs, rhs, .. } => fold_signed_div(lhs, rhs),
        MirOperationKind::URem { lhs, rhs, .. } => fold_unsigned_rem(lhs, rhs),
        MirOperationKind::SRem { lhs, rhs, .. } => fold_signed_rem(lhs, rhs),
        MirOperationKind::RotateLeft { lhs, rhs, .. } => fold_rotate_left(lhs, rhs),
        MirOperationKind::RotateRight { lhs, rhs, .. } => fold_rotate_right(lhs, rhs),
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => fold_select(condition, when_true, when_false),
        MirOperationKind::Concat { parts, ty } => fold_concat(parts, ty),
        MirOperationKind::Extract { value, lsb, ty } => fold_extract(value, *lsb, ty),
        MirOperationKind::Neg { value, .. } => fold_neg(value),
        MirOperationKind::Not { value, .. } => fold_not(value),
        MirOperationKind::Popcount { value, .. } => fold_popcount(value),
        MirOperationKind::CountLeadingZeros { value, .. } => fold_clz(value),
        MirOperationKind::CountTrailingZeros { value, .. } => fold_ctz(value),
        MirOperationKind::Icmp { op, lhs, rhs, .. } => fold_compare(*op, lhs, rhs),
        MirOperationKind::Cast { op, value, .. } => fold_cast(*op, value),
        MirOperationKind::FAdd { .. }
        | MirOperationKind::FSub { .. }
        | MirOperationKind::FMul { .. }
        | MirOperationKind::FDiv { .. }
        | MirOperationKind::Fcmp { .. }
        | MirOperationKind::Load { .. }
        | MirOperationKind::AddressOf { .. }
        | MirOperationKind::Store { .. }
        | MirOperationKind::MemoryCopy { .. }
        | MirOperationKind::Call { .. }
        | MirOperationKind::Intrinsic { .. } => None,
    }
}

fn fold_select(
    condition: &MirValue,
    when_true: &MirValue,
    when_false: &MirValue,
) -> Option<MirValue> {
    match condition {
        MirValue::Boolean(true) => Some(when_true.clone()),
        MirValue::Boolean(false) => Some(when_false.clone()),
        MirValue::Integer { value, .. } if *value == 0 => Some(when_false.clone()),
        MirValue::Integer { value, .. } if *value != 0 => Some(when_true.clone()),
        _ if when_true == when_false => Some(when_true.clone()),
        _ => None,
    }
}

fn fold_concat(parts: &[MirValue], ty: &crate::irs::mir::MirType) -> Option<MirValue> {
    let bits = match ty {
        crate::irs::mir::MirType::Integer(bits) => *bits,
        _ => return None,
    };
    if parts.is_empty() {
        return None;
    }

    let mut value = 0u128;
    let mut accumulated = 0u16;
    for part in parts {
        let MirValue::Integer {
            value: part_value,
            bits: part_bits,
        } = part
        else {
            return None;
        };
        let part_mask = if *part_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << part_bits) - 1
        };
        value = (value << *part_bits) | ((*part_value as u128) & part_mask);
        accumulated = accumulated.saturating_add(*part_bits);
    }

    if accumulated != bits {
        return None;
    }

    Some(MirValue::integer(value as i128, bits))
}

fn fold_extract(value: &MirValue, lsb: u16, ty: &crate::irs::mir::MirType) -> Option<MirValue> {
    let bits = match ty {
        crate::irs::mir::MirType::Integer(bits) => *bits,
        _ => return None,
    };
    match value {
        MirValue::Integer { value, .. } => {
            let mask = if bits >= 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            };
            let extracted = ((*value as u128) >> lsb) & mask;
            Some(MirValue::integer(extracted as i128, bits))
        }
        MirValue::Boolean(value) if lsb == 0 && bits == 1 => Some(MirValue::boolean(*value)),
        _ => None,
    }
}

fn fold_neg(value: &MirValue) -> Option<MirValue> {
    match value {
        MirValue::Integer { value, bits } => Some(MirValue::integer(-*value, *bits)),
        _ => None,
    }
}

fn fold_not(value: &MirValue) -> Option<MirValue> {
    match value {
        MirValue::Integer { value, bits } => Some(MirValue::integer(!*value, *bits)),
        MirValue::Boolean(value) => Some(MirValue::boolean(!*value)),
        _ => None,
    }
}

fn fold_popcount(value: &MirValue) -> Option<MirValue> {
    match value {
        MirValue::Integer { value, bits } => Some(MirValue::integer(
            (*value as u128).count_ones() as i128,
            *bits,
        )),
        MirValue::Boolean(value) => Some(MirValue::integer(if *value { 1 } else { 0 }, 1)),
        _ => None,
    }
}

fn fold_clz(value: &MirValue) -> Option<MirValue> {
    match value {
        MirValue::Integer { value, bits } => {
            let width = *bits as u32;
            if width == 0 {
                return None;
            }
            let masked = mask_to_width(*value as u128, width);
            let result = if masked == 0 {
                width as i128
            } else {
                ((width - 1) - (127 - masked.leading_zeros())) as i128
            };
            Some(MirValue::integer(result, *bits))
        }
        _ => None,
    }
}

fn fold_ctz(value: &MirValue) -> Option<MirValue> {
    match value {
        MirValue::Integer { value, bits } => {
            let width = *bits as u32;
            if width == 0 {
                return None;
            }
            let masked = mask_to_width(*value as u128, width);
            let result = if masked == 0 {
                width as i128
            } else {
                masked.trailing_zeros() as i128
            };
            Some(MirValue::integer(result, *bits))
        }
        _ => None,
    }
}

fn fold_integer_binary(
    lhs: &MirValue,
    rhs: &MirValue,
    fold: impl FnOnce(i128, i128) -> i128,
) -> Option<MirValue> {
    match (lhs, rhs) {
        (MirValue::Integer { value: left, bits }, MirValue::Integer { value: right, .. }) => {
            Some(MirValue::integer(fold(*left, *right), *bits))
        }
        _ => None,
    }
}

fn fold_unsigned_div(lhs: &MirValue, rhs: &MirValue) -> Option<MirValue> {
    match (lhs, rhs) {
        (MirValue::Integer { value: left, bits }, MirValue::Integer { value: right, .. })
            if *right != 0 =>
        {
            let width = *bits as u32;
            let left = mask_to_width(*left as u128, width);
            let right = mask_to_width(*right as u128, width);
            Some(MirValue::integer((left / right) as i128, *bits))
        }
        _ => None,
    }
}

fn fold_signed_div(lhs: &MirValue, rhs: &MirValue) -> Option<MirValue> {
    match (lhs, rhs) {
        (MirValue::Integer { value: left, bits }, MirValue::Integer { value: right, .. }) => left
            .checked_div(*right)
            .map(|value| MirValue::integer(value, *bits)),
        _ => None,
    }
}

fn fold_unsigned_rem(lhs: &MirValue, rhs: &MirValue) -> Option<MirValue> {
    match (lhs, rhs) {
        (MirValue::Integer { value: left, bits }, MirValue::Integer { value: right, .. })
            if *right != 0 =>
        {
            let width = *bits as u32;
            let left = mask_to_width(*left as u128, width);
            let right = mask_to_width(*right as u128, width);
            Some(MirValue::integer((left % right) as i128, *bits))
        }
        _ => None,
    }
}

fn fold_signed_rem(lhs: &MirValue, rhs: &MirValue) -> Option<MirValue> {
    match (lhs, rhs) {
        (MirValue::Integer { value: left, bits }, MirValue::Integer { value: right, .. }) => left
            .checked_rem(*right)
            .map(|value| MirValue::integer(value, *bits)),
        _ => None,
    }
}

fn fold_rotate_left(lhs: &MirValue, rhs: &MirValue) -> Option<MirValue> {
    match (lhs, rhs) {
        (MirValue::Integer { value: left, bits }, MirValue::Integer { value: right, .. }) => {
            let width = *bits as u32;
            if width == 0 {
                return None;
            }
            let masked = mask_to_width(*left as u128, width);
            let shift = (*right as u32) % width;
            let rotated = mask_to_width((masked << shift) | (masked >> (width - shift)), width);
            Some(MirValue::integer(rotated as i128, *bits))
        }
        _ => None,
    }
}

fn fold_rotate_right(lhs: &MirValue, rhs: &MirValue) -> Option<MirValue> {
    match (lhs, rhs) {
        (MirValue::Integer { value: left, bits }, MirValue::Integer { value: right, .. }) => {
            let width = *bits as u32;
            if width == 0 {
                return None;
            }
            let masked = mask_to_width(*left as u128, width);
            let shift = (*right as u32) % width;
            let rotated = mask_to_width((masked >> shift) | (masked << (width - shift)), width);
            Some(MirValue::integer(rotated as i128, *bits))
        }
        _ => None,
    }
}

fn mask_to_width(value: u128, width: u32) -> u128 {
    if width >= 128 {
        value
    } else {
        value & ((1u128 << width) - 1)
    }
}

fn fold_compare(op: MirCompareOperation, lhs: &MirValue, rhs: &MirValue) -> Option<MirValue> {
    match (lhs, rhs) {
        (MirValue::Integer { value: left, .. }, MirValue::Integer { value: right, .. }) => {
            let result = match op {
                MirCompareOperation::Eq => left == right,
                MirCompareOperation::Ne => left != right,
                MirCompareOperation::Ult
                | MirCompareOperation::Ule
                | MirCompareOperation::Ugt
                | MirCompareOperation::Uge
                | MirCompareOperation::Slt
                | MirCompareOperation::Sle
                | MirCompareOperation::Sgt
                | MirCompareOperation::Sge => compare_ordered(op, *left, *right),
            };
            Some(MirValue::boolean(result))
        }
        (MirValue::Boolean(left), MirValue::Boolean(right)) => match op {
            MirCompareOperation::Eq => Some(MirValue::boolean(left == right)),
            MirCompareOperation::Ne => Some(MirValue::boolean(left != right)),
            _ => None,
        },
        _ => None,
    }
}

fn compare_ordered(op: MirCompareOperation, lhs: i128, rhs: i128) -> bool {
    match op {
        MirCompareOperation::Ult | MirCompareOperation::Slt => lhs < rhs,
        MirCompareOperation::Ule | MirCompareOperation::Sle => lhs <= rhs,
        MirCompareOperation::Ugt | MirCompareOperation::Sgt => lhs > rhs,
        MirCompareOperation::Uge | MirCompareOperation::Sge => lhs >= rhs,
        MirCompareOperation::Eq => lhs == rhs,
        MirCompareOperation::Ne => lhs != rhs,
    }
}

fn fold_cast(op: MirCastOperation, value: &MirValue) -> Option<MirValue> {
    match op {
        MirCastOperation::Bitcast
        | MirCastOperation::Truncate
        | MirCastOperation::ZeroExtend
        | MirCastOperation::SignExtend => match value {
            MirValue::Integer { value, bits } => Some(MirValue::integer(*value, *bits)),
            MirValue::Boolean(value) => Some(MirValue::boolean(*value)),
            MirValue::Null { ty } => Some(MirValue::null(ty.clone())),
            MirValue::Undef { ty } => Some(MirValue::undef(ty.clone())),
            MirValue::Named { .. } => None,
        },
        MirCastOperation::IntToFloat
        | MirCastOperation::UIntToFloat
        | MirCastOperation::FloatToInt
        | MirCastOperation::FloatToUInt
        | MirCastOperation::FloatExtend
        | MirCastOperation::FloatTruncate => None,
    }
}
