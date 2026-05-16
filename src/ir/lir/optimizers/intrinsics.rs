use crate::ir::lir::{
    Lir, LirEffect, LirExpression, LirFunction, LirLocation, LirModule, LirTerminator,
};

pub fn optimize_intrinsics(lir: &mut Lir) {
    for effect in &mut lir.effects {
        optimize_effect(effect);
    }
    optimize_terminator(&mut lir.terminator);
}

pub fn optimize_intrinsics_function(function: &mut LirFunction) {
    for block in &mut function.blocks {
        for lir in &mut block.instructions {
            optimize_intrinsics(lir);
        }
    }
}

pub fn optimize_intrinsics_module(module: &mut LirModule) {
    for function in &mut module.functions {
        optimize_intrinsics_function(function);
    }
}

fn optimize_effect(effect: &mut LirEffect) {
    match effect {
        LirEffect::Intrinsic {
            name,
            args,
            outputs,
        } => {
            for arg in args.iter_mut() {
                optimize_expression(arg);
            }
            if name.trim().is_empty() && args.is_empty() && outputs.is_empty() {
                *effect = LirEffect::Nop;
            }
        }
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
        LirExpression::Intrinsic { name, args, bits } => {
            for arg in args.iter_mut() {
                optimize_expression(arg);
            }
            if name == "identity" && args.len() == 1 && args[0].bits() == *bits {
                *expression = args[0].clone();
            }
        }
        LirExpression::AddressOf { location, .. } | LirExpression::Read(location) => {
            optimize_location(location)
        }
        LirExpression::Load { addr, .. } => optimize_expression(addr),
        LirExpression::Unary { arg, .. }
        | LirExpression::Cast { arg, .. }
        | LirExpression::Extract { arg, .. } => optimize_expression(arg),
        LirExpression::Binary { left, right, .. } | LirExpression::Compare { left, right, .. } => {
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
        }
        LirExpression::Concat { parts, .. } => {
            for part in parts.iter_mut() {
                optimize_expression(part);
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
