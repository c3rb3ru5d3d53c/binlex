use crate::ir::lir::{
    Lir, LirEffect, LirExpression, LirLocation, LirModule, LirOperationBinary, LirTerminator,
};

pub fn optimize_identities(lir: &mut Lir) {
    for effect in &mut lir.effects {
        optimize_effect(effect);
    }
    optimize_terminator(&mut lir.terminator);
}

pub fn optimize_identities_module(module: &mut LirModule) {
    for lir in &mut module.semantics {
        optimize_identities(lir);
    }
}

fn optimize_effect(effect: &mut LirEffect) {
    match effect {
        LirEffect::Set { expression, .. }
        | LirEffect::Push { expression, .. }
        | LirEffect::Store { expression, .. } => optimize_expression(expression),
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
        LirExpression::Unary { arg, .. } | LirExpression::Cast { arg, .. } => {
            optimize_expression(arg)
        }
        LirExpression::Binary {
            op, left, right, ..
        } => {
            optimize_expression(left);
            optimize_expression(right);
            if let Some(result) = simplify_binary(*op, left, right) {
                *expression = result;
            }
        }
        LirExpression::Compare { left, right, .. } => {
            optimize_expression(left);
            optimize_expression(right);
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
            if when_true == when_false {
                *expression = (**when_true).clone();
            }
        }
        LirExpression::Extract { arg, .. } => optimize_expression(arg),
        LirExpression::Concat { parts, .. } => {
            for part in parts.iter_mut() {
                optimize_expression(part);
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
            optimize_expression(addr)
        }
        LirLocation::Register { .. }
        | LirLocation::Flag { .. }
        | LirLocation::ProgramCounter { .. }
        | LirLocation::Temporary { .. }
        | LirLocation::StackMemory { .. } => {}
    }
}

fn simplify_binary(
    op: LirOperationBinary,
    left: &LirExpression,
    right: &LirExpression,
) -> Option<LirExpression> {
    match op {
        LirOperationBinary::Add if is_zero(right) => Some(left.clone()),
        LirOperationBinary::Add if is_zero(left) => Some(right.clone()),
        LirOperationBinary::Sub if is_zero(right) => Some(left.clone()),
        LirOperationBinary::Mul if is_one(right) => Some(left.clone()),
        LirOperationBinary::Mul if is_one(left) => Some(right.clone()),
        LirOperationBinary::Mul if is_zero(right) => Some(zero_like(left.bits())),
        LirOperationBinary::Mul if is_zero(left) => Some(zero_like(right.bits())),
        LirOperationBinary::And if left == right => Some(left.clone()),
        LirOperationBinary::Or if left == right => Some(left.clone()),
        LirOperationBinary::Xor if is_zero(right) => Some(left.clone()),
        LirOperationBinary::Xor if is_zero(left) => Some(right.clone()),
        LirOperationBinary::Shl if is_zero(right) => Some(left.clone()),
        LirOperationBinary::LShr if is_zero(right) => Some(left.clone()),
        LirOperationBinary::AShr if is_zero(right) => Some(left.clone()),
        _ => None,
    }
}

fn is_zero(expression: &LirExpression) -> bool {
    matches!(
        expression,
        LirExpression::Const { value: 0, .. } | LirExpression::Null { .. }
    )
}

fn is_one(expression: &LirExpression) -> bool {
    matches!(expression, LirExpression::Const { value: 1, .. })
}

fn zero_like(bits: u16) -> LirExpression {
    LirExpression::Const { value: 0, bits }
}
