use crate::ir::lir::{Lir, LirEffect, LirExpression, LirLocation, LirTerminator};

pub fn normalize_instruction_lir(semantics: &Lir) -> Lir {
    Lir {
        version: semantics.version,
        status: semantics.status,
        abi: semantics.abi.clone(),
        encoding: semantics.encoding.clone(),
        temporaries: semantics.temporaries.clone(),
        effects: semantics.effects.iter().map(normalize_effect).collect(),
        terminator: normalize_terminator(&semantics.terminator),
        diagnostics: semantics.diagnostics.clone(),
    }
}

fn normalize_effect(effect: &LirEffect) -> LirEffect {
    match effect {
        LirEffect::Set { dst, expression } => LirEffect::Set {
            dst: normalize_location(dst),
            expression: normalize_expression(expression),
        },
        LirEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => LirEffect::Store {
            space: space.clone(),
            addr: normalize_expression(addr),
            expression: normalize_expression(expression),
            bits: *bits,
        },
        LirEffect::MemorySet {
            space,
            addr,
            value,
            count,
            element_bits,
            decrement,
        } => LirEffect::MemorySet {
            space: space.clone(),
            addr: normalize_expression(addr),
            value: normalize_expression(value),
            count: normalize_expression(count),
            element_bits: *element_bits,
            decrement: normalize_expression(decrement),
        },
        LirEffect::MemoryCopy {
            src_space,
            src_addr,
            dst_space,
            dst_addr,
            count,
            element_bits,
            decrement,
        } => LirEffect::MemoryCopy {
            src_space: src_space.clone(),
            src_addr: normalize_expression(src_addr),
            dst_space: dst_space.clone(),
            dst_addr: normalize_expression(dst_addr),
            count: normalize_expression(count),
            element_bits: *element_bits,
            decrement: normalize_expression(decrement),
        },
        LirEffect::AtomicCmpXchg {
            space,
            addr,
            expected,
            desired,
            bits,
            observed,
        } => LirEffect::AtomicCmpXchg {
            space: space.clone(),
            addr: normalize_expression(addr),
            expected: normalize_expression(expected),
            desired: normalize_expression(desired),
            bits: *bits,
            observed: normalize_location(observed),
        },
        LirEffect::WriteProperty {
            reference,
            name,
            expression,
            bits,
        } => LirEffect::WriteProperty {
            reference: normalize_expression(reference),
            name: name.clone(),
            expression: normalize_expression(expression),
            bits: *bits,
        },
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            bits,
        } => LirEffect::WriteElement {
            reference: normalize_expression(reference),
            index: normalize_expression(index),
            expression: normalize_expression(expression),
            bits: *bits,
        },
        LirEffect::Push { stack, expression } => LirEffect::Push {
            stack: stack.clone(),
            expression: normalize_expression(expression),
        },
        LirEffect::Pop { stack, dst } => LirEffect::Pop {
            stack: stack.clone(),
            dst: normalize_location(dst),
        },
        LirEffect::Fence { kind } => LirEffect::Fence { kind: kind.clone() },
        LirEffect::Trap { kind } => LirEffect::Trap { kind: kind.clone() },
        LirEffect::Intrinsic {
            name,
            args,
            outputs,
        } => LirEffect::Intrinsic {
            name: name.clone(),
            args: args.iter().map(normalize_expression).collect(),
            outputs: outputs.iter().map(normalize_location).collect(),
        },
        LirEffect::Nop => LirEffect::Nop,
    }
}

fn normalize_terminator(terminator: &LirTerminator) -> LirTerminator {
    match terminator {
        LirTerminator::FallThrough => LirTerminator::FallThrough,
        LirTerminator::Jump { target } => LirTerminator::Jump {
            target: normalize_expression(target),
        },
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => LirTerminator::Branch {
            condition: normalize_expression(condition),
            true_target: normalize_expression(true_target),
            false_target: normalize_expression(false_target),
        },
        LirTerminator::Call {
            target,
            return_target,
            does_return,
        } => LirTerminator::Call {
            target: normalize_expression(target),
            return_target: return_target.as_ref().map(normalize_expression),
            does_return: *does_return,
        },
        LirTerminator::Return { expression } => LirTerminator::Return {
            expression: expression.as_ref().map(normalize_expression),
        },
        LirTerminator::Unreachable => LirTerminator::Unreachable,
        LirTerminator::Trap => LirTerminator::Trap,
    }
}

fn normalize_location(location: &LirLocation) -> LirLocation {
    match location {
        LirLocation::Register { name, bits } => LirLocation::Register {
            name: name.clone(),
            bits: *bits,
        },
        LirLocation::Flag { name, bits } => LirLocation::Flag {
            name: name.clone(),
            bits: *bits,
        },
        LirLocation::ProgramCounter { bits } => LirLocation::ProgramCounter { bits: *bits },
        LirLocation::Temporary { id, bits } => LirLocation::Temporary {
            id: *id,
            bits: *bits,
        },
        LirLocation::Memory { space, addr, bits } => LirLocation::Memory {
            space: space.clone(),
            addr: Box::new(normalize_expression(addr)),
            bits: *bits,
        },
        LirLocation::IndexedMemory { name, index, bits } => LirLocation::IndexedMemory {
            name: name.clone(),
            index: Box::new(normalize_expression(index)),
            bits: *bits,
        },
        LirLocation::StackMemory { name, offset, bits } => LirLocation::StackMemory {
            name: name.clone(),
            offset: *offset,
            bits: *bits,
        },
    }
}

fn normalize_expression(expression: &LirExpression) -> LirExpression {
    match expression {
        LirExpression::Const { value, bits } => LirExpression::Const {
            value: *value,
            bits: *bits,
        },
        LirExpression::Function { name, bits } => LirExpression::Function {
            name: name.clone(),
            bits: *bits,
        },
        LirExpression::DataAddress { name, bits } => LirExpression::DataAddress {
            name: name.clone(),
            bits: *bits,
        },
        LirExpression::AddressOf { location, bits } => LirExpression::AddressOf {
            location: Box::new(normalize_location(location)),
            bits: *bits,
        },
        LirExpression::Read(location) => {
            LirExpression::Read(Box::new(normalize_location(location)))
        }
        LirExpression::Load { space, addr, bits } => LirExpression::Load {
            space: space.clone(),
            addr: Box::new(normalize_expression(addr)),
            bits: *bits,
        },
        LirExpression::Unary { op, arg, bits } => LirExpression::Unary {
            op: *op,
            arg: Box::new(normalize_expression(arg)),
            bits: *bits,
        },
        LirExpression::Binary {
            op,
            left,
            right,
            bits,
        } => LirExpression::Binary {
            op: *op,
            left: Box::new(normalize_expression(left)),
            right: Box::new(normalize_expression(right)),
            bits: *bits,
        },
        LirExpression::Cast { op, arg, bits } => LirExpression::Cast {
            op: *op,
            arg: Box::new(normalize_expression(arg)),
            bits: *bits,
        },
        LirExpression::Compare {
            op,
            left,
            right,
            bits,
        } => LirExpression::Compare {
            op: *op,
            left: Box::new(normalize_expression(left)),
            right: Box::new(normalize_expression(right)),
            bits: *bits,
        },
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            bits,
        } => LirExpression::Select {
            condition: Box::new(normalize_expression(condition)),
            when_true: Box::new(normalize_expression(when_true)),
            when_false: Box::new(normalize_expression(when_false)),
            bits: *bits,
        },
        LirExpression::Extract { arg, lsb, bits } => LirExpression::Extract {
            arg: Box::new(normalize_expression(arg)),
            lsb: *lsb,
            bits: *bits,
        },
        LirExpression::Concat { parts, bits } => LirExpression::Concat {
            parts: parts.iter().map(normalize_expression).collect(),
            bits: *bits,
        },
        LirExpression::Undefined { bits } => LirExpression::Undefined { bits: *bits },
        LirExpression::Poison { bits } => LirExpression::Poison { bits: *bits },
        LirExpression::Intrinsic { name, args, bits } => LirExpression::Intrinsic {
            name: name.clone(),
            args: args.iter().map(normalize_expression).collect(),
            bits: *bits,
        },
        LirExpression::Null { bits } => LirExpression::Null { bits: *bits },
        LirExpression::Allocate { kind, bits } => LirExpression::Allocate {
            kind: kind.clone(),
            bits: *bits,
        },
        LirExpression::ReadProperty {
            reference,
            name,
            bits,
        } => LirExpression::ReadProperty {
            reference: Box::new(normalize_expression(reference)),
            name: name.clone(),
            bits: *bits,
        },
        LirExpression::ReadElement {
            reference,
            index,
            bits,
        } => LirExpression::ReadElement {
            reference: Box::new(normalize_expression(reference)),
            index: Box::new(normalize_expression(index)),
            bits: *bits,
        },
    }
}
