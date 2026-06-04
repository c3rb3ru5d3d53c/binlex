use crate::irs::mir::{
    Mir, MirAddressSpace, MirOperation, MirOperationKind, MirTerminator, MirType, MirValue,
};
use std::collections::{HashMap, HashSet};

type AliasMap = HashMap<String, MirValue>;
type DefMap = HashMap<String, MirOperationKind>;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct StackCell {
    address: MirValue,
    ty: MirType,
}

pub fn optimize_stack(mir: &mut Mir) {
    for block in mir.blocks_mut() {
        let mut aliases = AliasMap::new();
        let mut defs = DefMap::new();
        let mut optimized = Vec::with_capacity(block.operations.len());
        let preserve_path_aliases =
            matches!(block.terminator.as_ref(), Some(MirTerminator::Jump { .. }));

        for mut operation in std::mem::take(&mut block.operations) {
            rewrite_operation(&mut operation, &aliases);

            if let Some(simplified) = simplify_operation(&operation.kind, &defs) {
                operation.kind = simplified;
            }

            if let Some((result, alias)) = alias_from_operation(&operation) {
                aliases.insert(result, alias);
                if !preserve_path_aliases {
                    continue;
                }
            }

            if let Some(result) = operation.result.as_ref() {
                aliases.remove(result);
                defs.insert(result.clone(), operation.kind.clone());
            }

            optimized.push(operation);
        }

        if let Some(terminator) = block.terminator.as_mut() {
            rewrite_terminator(terminator, &aliases);
        }

        block.operations = remove_dead_stack_stores(optimized);
    }
}

fn simplify_operation(kind: &MirOperationKind, defs: &DefMap) -> Option<MirOperationKind> {
    match kind {
        MirOperationKind::Add { lhs, rhs, ty } => match simplify_add(lhs, rhs, ty, defs) {
            Some((lhs, rhs)) if integer_value(&rhs) == Some(0) => Some(MirOperationKind::Copy {
                value: lhs,
                ty: ty.clone(),
            }),
            Some((lhs, rhs)) => Some(MirOperationKind::Add {
                lhs,
                rhs,
                ty: ty.clone(),
            }),
            None => None,
        },
        MirOperationKind::Sub { lhs, rhs, ty } => match simplify_sub(lhs, rhs, ty, defs) {
            SimplifiedArithmetic::Alias(value) => Some(MirOperationKind::Copy {
                value,
                ty: ty.clone(),
            }),
            SimplifiedArithmetic::Add(lhs, rhs) => Some(MirOperationKind::Add {
                lhs,
                rhs,
                ty: ty.clone(),
            }),
            SimplifiedArithmetic::Sub(lhs, rhs) => Some(MirOperationKind::Sub {
                lhs,
                rhs,
                ty: ty.clone(),
            }),
            SimplifiedArithmetic::Unchanged => None,
        },
        _ => None,
    }
}

fn simplify_add(
    lhs: &MirValue,
    rhs: &MirValue,
    ty: &MirType,
    defs: &DefMap,
) -> Option<(MirValue, MirValue)> {
    let (base, offset) = accumulate_offset(lhs, 0, defs)?;
    let rhs_offset = integer_value(rhs)?;
    let total = offset + rhs_offset;
    Some((base, MirValue::integer(total, type_bits(ty)?)))
}

enum SimplifiedArithmetic {
    Alias(MirValue),
    Add(MirValue, MirValue),
    Sub(MirValue, MirValue),
    Unchanged,
}

fn simplify_sub(
    lhs: &MirValue,
    rhs: &MirValue,
    ty: &MirType,
    defs: &DefMap,
) -> SimplifiedArithmetic {
    let Some((base, offset)) = accumulate_offset(lhs, 0, defs) else {
        return SimplifiedArithmetic::Unchanged;
    };
    let Some(rhs_offset) = integer_value(rhs) else {
        return SimplifiedArithmetic::Unchanged;
    };
    let total = offset - rhs_offset;
    if total == 0 {
        return SimplifiedArithmetic::Alias(base);
    }
    if total > 0 {
        return SimplifiedArithmetic::Add(
            base,
            MirValue::integer(total, type_bits(ty).unwrap_or(64)),
        );
    }
    SimplifiedArithmetic::Sub(
        base,
        MirValue::integer((-total) as i128, type_bits(ty).unwrap_or(64)),
    )
}

fn accumulate_offset(value: &MirValue, offset: i128, defs: &DefMap) -> Option<(MirValue, i128)> {
    match value {
        MirValue::Named { name, .. } => match defs.get(name) {
            Some(MirOperationKind::Add { lhs, rhs, .. }) => {
                if let Some(rhs_offset) = integer_value(rhs) {
                    accumulate_offset(lhs, offset + rhs_offset, defs)
                } else if let Some(lhs_offset) = integer_value(lhs) {
                    accumulate_offset(rhs, offset + lhs_offset, defs)
                } else {
                    Some((value.clone(), offset))
                }
            }
            Some(MirOperationKind::Sub { lhs, rhs, .. }) => {
                if let Some(rhs_offset) = integer_value(rhs) {
                    accumulate_offset(lhs, offset - rhs_offset, defs)
                } else {
                    Some((value.clone(), offset))
                }
            }
            _ => Some((value.clone(), offset)),
        },
        _ => Some((value.clone(), offset)),
    }
}

fn integer_value(value: &MirValue) -> Option<i128> {
    match value {
        MirValue::Integer { value, .. } => Some(*value),
        _ => None,
    }
}

fn type_bits(ty: &MirType) -> Option<u16> {
    match ty {
        MirType::Integer(bits) => Some(*bits),
        _ => None,
    }
}

fn alias_from_operation(operation: &MirOperation) -> Option<(String, MirValue)> {
    let result = operation.result.clone()?;
    match &operation.kind {
        MirOperationKind::Copy { value, .. } => Some((result, value.clone())),
        MirOperationKind::Add { lhs, rhs, .. } if is_integer_zero(rhs) => {
            Some((result, lhs.clone()))
        }
        MirOperationKind::Add { lhs, rhs, .. } if is_integer_zero(lhs) => {
            Some((result, rhs.clone()))
        }
        MirOperationKind::Sub { lhs, rhs, .. } if is_integer_zero(rhs) => {
            Some((result, lhs.clone()))
        }
        _ => None,
    }
}

fn is_integer_zero(value: &MirValue) -> bool {
    matches!(value, MirValue::Integer { value: 0, .. })
}

fn rewrite_operation(operation: &mut MirOperation, aliases: &AliasMap) {
    match &mut operation.kind {
        MirOperationKind::Copy { value, .. } => rewrite_value(value, aliases),
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
            rewrite_value(lhs, aliases);
            rewrite_value(rhs, aliases);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                rewrite_value(part, aliases);
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_value(condition, aliases);
            rewrite_value(when_true, aliases);
            rewrite_value(when_false, aliases);
        }
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Load { address: value, .. }
        | MirOperationKind::AddressOf { address: value, .. }
        | MirOperationKind::Cast { value, .. } => {
            rewrite_value(value, aliases);
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, aliases);
            rewrite_value(value, aliases);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_value(src_address, aliases);
            rewrite_value(dst_address, aliases);
            rewrite_value(count, aliases);
            rewrite_value(decrement, aliases);
        }
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, aliases);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, aliases: &AliasMap) {
    match terminator {
        MirTerminator::Jump { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, aliases);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            rewrite_value(condition, aliases);
            for argument in then_arguments {
                rewrite_value(argument, aliases);
            }
            for argument in else_arguments {
                rewrite_value(argument, aliases);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_value(value, aliases);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_value(value: &mut MirValue, aliases: &AliasMap) {
    if let MirValue::Named { name, .. } = value {
        if let Some(replacement) = aliases.get(name) {
            *value = replacement.clone();
        }
    }
}

fn remove_dead_stack_stores(operations: Vec<MirOperation>) -> Vec<MirOperation> {
    let mut live_stack_cells = HashSet::<StackCell>::new();
    let mut barrier = false;
    let mut kept = Vec::with_capacity(operations.len());

    for operation in operations.into_iter().rev() {
        match &operation.kind {
            MirOperationKind::Load {
                address_space: MirAddressSpace::Stack,
                address,
                ty,
            } => {
                live_stack_cells.insert(StackCell {
                    address: address.clone(),
                    ty: ty.clone(),
                });
                kept.push(operation);
            }
            MirOperationKind::Store {
                address_space: MirAddressSpace::Stack,
                address,
                value: _,
                ty,
            } => {
                let cell = StackCell {
                    address: address.clone(),
                    ty: ty.clone(),
                };
                if barrier || live_stack_cells.remove(&cell) {
                    kept.push(operation);
                }
            }
            MirOperationKind::Call { .. } | MirOperationKind::Intrinsic { .. } => {
                barrier = true;
                live_stack_cells.clear();
                kept.push(operation);
            }
            _ => kept.push(operation),
        }
    }

    kept.reverse();
    kept
}
