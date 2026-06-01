use crate::ir::mir::{Mir, MirOperation, MirOperationKind, MirTerminator, MirType, MirValue};
use std::collections::HashMap;

type AliasMap = HashMap<String, MirValue>;
type SeenMap = HashMap<MirOperationKind, MirValue>;

pub fn optimize_subexpressions(mir: &mut Mir) {
    for block in mir.blocks_mut() {
        let mut aliases = AliasMap::new();
        let mut seen = SeenMap::new();
        let mut optimized = Vec::with_capacity(block.operations.len());

        for mut operation in std::mem::take(&mut block.operations) {
            rewrite_operation(&mut operation, &aliases);

            let Some(result) = operation.result.clone() else {
                optimized.push(operation);
                continue;
            };

            if is_pure(&operation.kind) {
                if let Some(existing) = seen.get(&operation.kind).cloned() {
                    aliases.insert(result, existing);
                    continue;
                }

                let ty = result_type(&operation.kind);
                seen.insert(operation.kind.clone(), MirValue::named(result.clone(), ty));
            }

            aliases.remove(&result);
            optimized.push(operation);
        }

        if let Some(terminator) = block.terminator.as_mut() {
            rewrite_terminator(terminator, &aliases);
        }

        block.operations = optimized;
    }
}

fn is_pure(kind: &MirOperationKind) -> bool {
    match kind {
        MirOperationKind::Copy { .. }
        | MirOperationKind::Add { .. }
        | MirOperationKind::Sub { .. }
        | MirOperationKind::Mul { .. }
        | MirOperationKind::FAdd { .. }
        | MirOperationKind::FSub { .. }
        | MirOperationKind::FMul { .. }
        | MirOperationKind::FDiv { .. }
        | MirOperationKind::And { .. }
        | MirOperationKind::Or { .. }
        | MirOperationKind::Xor { .. }
        | MirOperationKind::Shl { .. }
        | MirOperationKind::LShr { .. }
        | MirOperationKind::AShr { .. }
        | MirOperationKind::UDiv { .. }
        | MirOperationKind::SDiv { .. }
        | MirOperationKind::URem { .. }
        | MirOperationKind::SRem { .. }
        | MirOperationKind::RotateLeft { .. }
        | MirOperationKind::RotateRight { .. }
        | MirOperationKind::Select { .. }
        | MirOperationKind::Concat { .. }
        | MirOperationKind::Extract { .. }
        | MirOperationKind::Neg { .. }
        | MirOperationKind::Not { .. }
        | MirOperationKind::Popcount { .. }
        | MirOperationKind::CountLeadingZeros { .. }
        | MirOperationKind::CountTrailingZeros { .. }
        | MirOperationKind::Icmp { .. }
        | MirOperationKind::Fcmp { .. }
        | MirOperationKind::AddressOf { .. }
        | MirOperationKind::Cast { .. } => true,
        MirOperationKind::Intrinsic { name, .. } => {
            name.starts_with("lir.binary.")
                || name.starts_with("lir.unary.")
                || name.starts_with("lir.expr.")
                || name.starts_with("lir.compare.")
                || name.starts_with("lir.cast.")
        }
        MirOperationKind::Load { .. }
        | MirOperationKind::Store { .. }
        | MirOperationKind::MemoryCopy { .. }
        | MirOperationKind::Call { .. } => false,
    }
}

fn rewrite_operation(operation: &mut MirOperation, aliases: &AliasMap) {
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
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. } => rewrite_value(value, aliases),
        MirOperationKind::Load { address, .. } | MirOperationKind::AddressOf { address, .. } => {
            rewrite_value(address, aliases)
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
        MirOperationKind::Cast { value, .. } => rewrite_value(value, aliases),
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

fn result_type(kind: &MirOperationKind) -> MirType {
    match kind {
        MirOperationKind::Copy { ty, .. }
        | MirOperationKind::Add { ty, .. }
        | MirOperationKind::Sub { ty, .. }
        | MirOperationKind::Mul { ty, .. }
        | MirOperationKind::FAdd { ty, .. }
        | MirOperationKind::FSub { ty, .. }
        | MirOperationKind::FMul { ty, .. }
        | MirOperationKind::FDiv { ty, .. }
        | MirOperationKind::And { ty, .. }
        | MirOperationKind::Or { ty, .. }
        | MirOperationKind::Xor { ty, .. }
        | MirOperationKind::Shl { ty, .. }
        | MirOperationKind::LShr { ty, .. }
        | MirOperationKind::AShr { ty, .. }
        | MirOperationKind::UDiv { ty, .. }
        | MirOperationKind::SDiv { ty, .. }
        | MirOperationKind::URem { ty, .. }
        | MirOperationKind::SRem { ty, .. }
        | MirOperationKind::RotateLeft { ty, .. }
        | MirOperationKind::RotateRight { ty, .. }
        | MirOperationKind::Select { ty, .. }
        | MirOperationKind::Concat { ty, .. }
        | MirOperationKind::Extract { ty, .. }
        | MirOperationKind::Neg { ty, .. }
        | MirOperationKind::Not { ty, .. }
        | MirOperationKind::Popcount { ty, .. }
        | MirOperationKind::CountLeadingZeros { ty, .. }
        | MirOperationKind::CountTrailingZeros { ty, .. }
        | MirOperationKind::Load { ty, .. }
        | MirOperationKind::AddressOf { ty, .. }
        | MirOperationKind::Icmp { ty, .. }
        | MirOperationKind::Fcmp { ty, .. }
        | MirOperationKind::Cast { ty, .. } => ty.clone(),
        MirOperationKind::Call { result_types, .. }
        | MirOperationKind::Intrinsic { result_types, .. } => {
            result_types.first().cloned().unwrap_or_else(MirType::void)
        }
        MirOperationKind::Store { .. } | MirOperationKind::MemoryCopy { .. } => MirType::void(),
    }
}
