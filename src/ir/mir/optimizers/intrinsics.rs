use crate::ir::mir::{Mir, MirOperation, MirOperationKind, MirTerminator, MirValue};
use std::collections::HashMap;

type AliasMap = HashMap<String, MirValue>;

pub fn optimize_intrinsics(mir: &mut Mir) {
    for block in mir.blocks_mut() {
        let mut aliases = AliasMap::new();
        let mut optimized = Vec::with_capacity(block.operations.len());

        for mut operation in std::mem::take(&mut block.operations) {
            rewrite_operation(&mut operation, &aliases);

            let Some(result) = operation.result.clone() else {
                optimized.push(operation);
                continue;
            };

            if let Some(alias) = simplify_intrinsic(&operation.kind) {
                aliases.insert(result, alias);
                continue;
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

fn simplify_intrinsic(kind: &MirOperationKind) -> Option<MirValue> {
    let MirOperationKind::Intrinsic {
        name,
        arguments,
        result_types,
    } = kind
    else {
        return None;
    };

    let result_ty = result_types.first()?.clone();

    match (name.as_str(), arguments.as_slice()) {
        ("lir.binary.xor", [lhs, rhs]) if lhs == rhs => Some(zero_like(lhs, &result_ty)),
        ("lir.binary.and", [lhs, rhs]) if lhs == rhs => Some(lhs.clone()),
        ("lir.binary.or", [lhs, rhs]) if lhs == rhs => Some(lhs.clone()),
        ("lir.binary.shl", [lhs, MirValue::Integer { value: 0, .. }]) => Some(lhs.clone()),
        ("lir.binary.lshr", [lhs, MirValue::Integer { value: 0, .. }]) => Some(lhs.clone()),
        ("lir.expr.select", [MirValue::Boolean(true), when_true, _]) => Some(when_true.clone()),
        ("lir.expr.select", [MirValue::Boolean(false), _, when_false]) => Some(when_false.clone()),
        ("lir.expr.select", [MirValue::Integer { value, .. }, when_true, when_false]) => {
            if *value == 0 {
                Some(when_false.clone())
            } else {
                Some(when_true.clone())
            }
        }
        ("lir.expr.select", [_, when_true, when_false]) if when_true == when_false => {
            Some(when_true.clone())
        }
        _ => None,
    }
}

fn zero_like(value: &MirValue, fallback_ty: &crate::ir::mir::MirType) -> MirValue {
    match value {
        MirValue::Integer { bits, .. } => MirValue::integer(0, *bits),
        MirValue::Boolean(_) => MirValue::boolean(false),
        MirValue::Named { ty, .. } | MirValue::Null { ty } | MirValue::Undef { ty } => match ty {
            crate::ir::mir::MirType::Integer(bits) => MirValue::integer(0, *bits),
            _ => MirValue::null(ty.clone()),
        },
    }
    .or_fallback(fallback_ty)
}

trait FallbackValue {
    fn or_fallback(self, fallback_ty: &crate::ir::mir::MirType) -> MirValue;
}

impl FallbackValue for MirValue {
    fn or_fallback(self, _fallback_ty: &crate::ir::mir::MirType) -> MirValue {
        self
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
