use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation, SemanticTerminator,
};

pub fn normalize_instruction_semantics(semantics: &InstructionSemantics) -> InstructionSemantics {
    InstructionSemantics {
        version: semantics.version,
        status: semantics.status,
        temporaries: semantics.temporaries.clone(),
        effects: semantics.effects.iter().map(normalize_effect).collect(),
        terminator: normalize_terminator(&semantics.terminator),
        diagnostics: semantics.diagnostics.clone(),
    }
}

fn normalize_effect(effect: &SemanticEffect) -> SemanticEffect {
    match effect {
        SemanticEffect::Set { dst, expression } => SemanticEffect::Set {
            dst: normalize_location(dst),
            expression: normalize_expression(expression),
        },
        SemanticEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => SemanticEffect::Store {
            space: space.clone(),
            addr: normalize_expression(addr),
            expression: normalize_expression(expression),
            bits: *bits,
        },
        SemanticEffect::MemorySet {
            space,
            addr,
            value,
            count,
            element_bits,
            decrement,
        } => SemanticEffect::MemorySet {
            space: space.clone(),
            addr: normalize_expression(addr),
            value: normalize_expression(value),
            count: normalize_expression(count),
            element_bits: *element_bits,
            decrement: normalize_expression(decrement),
        },
        SemanticEffect::MemoryCopy {
            src_space,
            src_addr,
            dst_space,
            dst_addr,
            count,
            element_bits,
            decrement,
        } => SemanticEffect::MemoryCopy {
            src_space: src_space.clone(),
            src_addr: normalize_expression(src_addr),
            dst_space: dst_space.clone(),
            dst_addr: normalize_expression(dst_addr),
            count: normalize_expression(count),
            element_bits: *element_bits,
            decrement: normalize_expression(decrement),
        },
        SemanticEffect::AtomicCmpXchg {
            space,
            addr,
            expected,
            desired,
            bits,
            observed,
        } => SemanticEffect::AtomicCmpXchg {
            space: space.clone(),
            addr: normalize_expression(addr),
            expected: normalize_expression(expected),
            desired: normalize_expression(desired),
            bits: *bits,
            observed: normalize_location(observed),
        },
        SemanticEffect::Fence { kind } => SemanticEffect::Fence { kind: kind.clone() },
        SemanticEffect::Trap { kind } => SemanticEffect::Trap { kind: kind.clone() },
        SemanticEffect::Architecture {
            name,
            args,
            outputs,
        } => SemanticEffect::Architecture {
            name: name.clone(),
            args: args.iter().map(normalize_expression).collect(),
            outputs: outputs.iter().map(normalize_location).collect(),
        },
        SemanticEffect::Intrinsic {
            name,
            args,
            outputs,
        } => SemanticEffect::Intrinsic {
            name: name.clone(),
            args: args.iter().map(normalize_expression).collect(),
            outputs: outputs.iter().map(normalize_location).collect(),
        },
        SemanticEffect::Nop => SemanticEffect::Nop,
    }
}

fn normalize_terminator(terminator: &SemanticTerminator) -> SemanticTerminator {
    match terminator {
        SemanticTerminator::FallThrough => SemanticTerminator::FallThrough,
        SemanticTerminator::Jump { target } => SemanticTerminator::Jump {
            target: normalize_expression(target),
        },
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => SemanticTerminator::Branch {
            condition: normalize_expression(condition),
            true_target: normalize_expression(true_target),
            false_target: normalize_expression(false_target),
        },
        SemanticTerminator::Call {
            target,
            return_target,
            does_return,
        } => SemanticTerminator::Call {
            target: normalize_expression(target),
            return_target: return_target.as_ref().map(normalize_expression),
            does_return: *does_return,
        },
        SemanticTerminator::Return { expression } => SemanticTerminator::Return {
            expression: expression.as_ref().map(normalize_expression),
        },
        SemanticTerminator::Unreachable => SemanticTerminator::Unreachable,
        SemanticTerminator::Trap => SemanticTerminator::Trap,
    }
}

fn normalize_location(location: &SemanticLocation) -> SemanticLocation {
    match location {
        SemanticLocation::Register { name, bits } => SemanticLocation::Register {
            name: name.clone(),
            bits: *bits,
        },
        SemanticLocation::Flag { name, bits } => SemanticLocation::Flag {
            name: name.clone(),
            bits: *bits,
        },
        SemanticLocation::ProgramCounter { bits } => {
            SemanticLocation::ProgramCounter { bits: *bits }
        }
        SemanticLocation::Temporary { id, bits } => SemanticLocation::Temporary {
            id: *id,
            bits: *bits,
        },
        SemanticLocation::Memory { space, addr, bits } => SemanticLocation::Memory {
            space: space.clone(),
            addr: Box::new(normalize_expression(addr)),
            bits: *bits,
        },
    }
}

fn normalize_expression(expression: &SemanticExpression) -> SemanticExpression {
    match expression {
        SemanticExpression::Const { value, bits } => SemanticExpression::Const {
            value: *value,
            bits: *bits,
        },
        SemanticExpression::Read(location) => {
            SemanticExpression::Read(Box::new(normalize_location(location)))
        }
        SemanticExpression::Load { space, addr, bits } => SemanticExpression::Load {
            space: space.clone(),
            addr: Box::new(normalize_expression(addr)),
            bits: *bits,
        },
        SemanticExpression::Unary { op, arg, bits } => SemanticExpression::Unary {
            op: *op,
            arg: Box::new(normalize_expression(arg)),
            bits: *bits,
        },
        SemanticExpression::Binary {
            op,
            left,
            right,
            bits,
        } => SemanticExpression::Binary {
            op: *op,
            left: Box::new(normalize_expression(left)),
            right: Box::new(normalize_expression(right)),
            bits: *bits,
        },
        SemanticExpression::Cast { op, arg, bits } => SemanticExpression::Cast {
            op: *op,
            arg: Box::new(normalize_expression(arg)),
            bits: *bits,
        },
        SemanticExpression::Compare {
            op,
            left,
            right,
            bits,
        } => SemanticExpression::Compare {
            op: *op,
            left: Box::new(normalize_expression(left)),
            right: Box::new(normalize_expression(right)),
            bits: *bits,
        },
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            bits,
        } => SemanticExpression::Select {
            condition: Box::new(normalize_expression(condition)),
            when_true: Box::new(normalize_expression(when_true)),
            when_false: Box::new(normalize_expression(when_false)),
            bits: *bits,
        },
        SemanticExpression::Extract { arg, lsb, bits } => SemanticExpression::Extract {
            arg: Box::new(normalize_expression(arg)),
            lsb: *lsb,
            bits: *bits,
        },
        SemanticExpression::Concat { parts, bits } => SemanticExpression::Concat {
            parts: parts.iter().map(normalize_expression).collect(),
            bits: *bits,
        },
        SemanticExpression::Undefined { bits } => SemanticExpression::Undefined { bits: *bits },
        SemanticExpression::Poison { bits } => SemanticExpression::Poison { bits: *bits },
        SemanticExpression::Architecture { name, args, bits } => {
            SemanticExpression::Architecture {
                name: name.clone(),
                args: args.iter().map(normalize_expression).collect(),
                bits: *bits,
            }
        }
        SemanticExpression::Intrinsic { name, args, bits } => SemanticExpression::Intrinsic {
            name: name.clone(),
            args: args.iter().map(normalize_expression).collect(),
            bits: *bits,
        },
    }
}
