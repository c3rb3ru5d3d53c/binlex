use crate::lifters::llvm::abi::{coerce_expression_width, normalize_shift_binary};
use crate::semantics::passes::{normalize_instruction_semantics, validate_instruction_semantics};
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticTerminator,
};
use std::io::Error;

pub fn prepare_instruction_semantics(
    semantics: &InstructionSemantics,
) -> Result<InstructionSemantics, Error> {
    validate_instruction_semantics(semantics)?;
    let normalized = normalize_instruction_semantics(semantics);
    Ok(InstructionSemantics {
        version: normalized.version,
        status: normalized.status,
        temporaries: normalized.temporaries,
        effects: normalized.effects.iter().map(prepare_effect).collect(),
        terminator: prepare_terminator(&normalized.terminator),
        diagnostics: normalized.diagnostics,
    })
}

fn prepare_effect(effect: &SemanticEffect) -> SemanticEffect {
    match effect {
        SemanticEffect::Set { dst, expression } => match dst {
            crate::semantics::SemanticLocation::Memory { bits, .. } => SemanticEffect::Set {
                dst: dst.clone(),
                expression: prepare_expression(&coerce_expression_width(expression.clone(), *bits)),
            },
            _ => SemanticEffect::Set {
                dst: dst.clone(),
                expression: prepare_expression(expression),
            },
        },
        SemanticEffect::Store {
            space,
            addr,
            expression,
            bits,
        } => SemanticEffect::Store {
            space: space.clone(),
            addr: prepare_expression(addr),
            expression: prepare_expression(&coerce_expression_width(expression.clone(), *bits)),
            bits: *bits,
        },
        SemanticEffect::Fence { kind } => SemanticEffect::Fence { kind: kind.clone() },
        SemanticEffect::Trap { kind } => SemanticEffect::Trap { kind: kind.clone() },
        SemanticEffect::Intrinsic {
            name,
            args,
            outputs,
        } => SemanticEffect::Intrinsic {
            name: name.clone(),
            args: args.iter().map(prepare_expression).collect(),
            outputs: outputs.clone(),
        },
        SemanticEffect::Nop => SemanticEffect::Nop,
    }
}

fn prepare_terminator(terminator: &SemanticTerminator) -> SemanticTerminator {
    match terminator {
        SemanticTerminator::FallThrough => SemanticTerminator::FallThrough,
        SemanticTerminator::Jump { target } => SemanticTerminator::Jump {
            target: prepare_expression(target),
        },
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => SemanticTerminator::Branch {
            condition: prepare_expression(condition),
            true_target: prepare_expression(true_target),
            false_target: prepare_expression(false_target),
        },
        SemanticTerminator::Call {
            target,
            return_target,
            does_return,
        } => SemanticTerminator::Call {
            target: prepare_expression(target),
            return_target: return_target.as_ref().map(prepare_expression),
            does_return: *does_return,
        },
        SemanticTerminator::Return { expression } => SemanticTerminator::Return {
            expression: expression.as_ref().map(prepare_expression),
        },
        SemanticTerminator::Unreachable => SemanticTerminator::Unreachable,
        SemanticTerminator::Trap => SemanticTerminator::Trap,
    }
}

fn prepare_expression(expression: &SemanticExpression) -> SemanticExpression {
    match expression {
        SemanticExpression::Const { value, bits } => SemanticExpression::Const {
            value: *value,
            bits: *bits,
        },
        SemanticExpression::Read(location) => SemanticExpression::Read(location.clone()),
        SemanticExpression::Load { space, addr, bits } => SemanticExpression::Load {
            space: space.clone(),
            addr: Box::new(prepare_expression(addr)),
            bits: *bits,
        },
        SemanticExpression::Unary { op, arg, bits } => SemanticExpression::Unary {
            op: *op,
            arg: Box::new(prepare_expression(arg)),
            bits: *bits,
        },
        SemanticExpression::Binary {
            op,
            left,
            right,
            bits,
        } => {
            let left = prepare_expression(left);
            let right = prepare_expression(right);
            let (left, right) = normalize_shift_binary(*op, left, right, *bits);
            SemanticExpression::Binary {
                op: *op,
                left: Box::new(left),
                right: Box::new(right),
                bits: *bits,
            }
        }
        SemanticExpression::Cast { op, arg, bits } => SemanticExpression::Cast {
            op: *op,
            arg: Box::new(prepare_expression(arg)),
            bits: *bits,
        },
        SemanticExpression::Compare {
            op,
            left,
            right,
            bits,
        } => SemanticExpression::Compare {
            op: *op,
            left: Box::new(prepare_expression(left)),
            right: Box::new(prepare_expression(right)),
            bits: *bits,
        },
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            bits,
        } => SemanticExpression::Select {
            condition: Box::new(prepare_expression(condition)),
            when_true: Box::new(prepare_expression(when_true)),
            when_false: Box::new(prepare_expression(when_false)),
            bits: *bits,
        },
        SemanticExpression::Extract { arg, lsb, bits } => SemanticExpression::Extract {
            arg: Box::new(prepare_expression(arg)),
            lsb: *lsb,
            bits: *bits,
        },
        SemanticExpression::Concat { parts, bits } => SemanticExpression::Concat {
            parts: parts.iter().map(prepare_expression).collect(),
            bits: *bits,
        },
        SemanticExpression::Undefined { bits } => SemanticExpression::Undefined { bits: *bits },
        SemanticExpression::Poison { bits } => SemanticExpression::Poison { bits: *bits },
        SemanticExpression::Intrinsic { name, args, bits } => SemanticExpression::Intrinsic {
            name: name.clone(),
            args: args.iter().map(prepare_expression).collect(),
            bits: *bits,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::prepare_instruction_semantics;
    use crate::semantics::{
        InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
        SemanticLocation, SemanticOperationBinary, SemanticStatus, SemanticTerminator,
    };

    #[test]
    fn coerces_store_expression_to_destination_width() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: SemanticExpression::Const { value: 0, bits: 64 },
                expression: SemanticExpression::Read(Box::new(SemanticLocation::Register {
                    name: "wide".to_string(),
                    bits: 128,
                })),
                bits: 64,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            SemanticEffect::Store { expression, .. } => match expression {
                SemanticExpression::Cast { bits, .. } => assert_eq!(*bits, 64),
                other => panic!("expected cast, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }

    #[test]
    fn widens_shift_amount_to_operation_width() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "dst".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::LShr,
                    left: Box::new(SemanticExpression::Const { value: 7, bits: 32 }),
                    right: Box::new(SemanticExpression::Const { value: 3, bits: 5 }),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        let prepared = prepare_instruction_semantics(&semantics).expect("prepare");
        match &prepared.effects[0] {
            SemanticEffect::Set { expression, .. } => match expression {
                SemanticExpression::Binary { right, .. } => match right.as_ref() {
                    SemanticExpression::Cast { bits, .. } => assert_eq!(*bits, 32),
                    other => panic!("expected cast, got {:?}", other),
                },
                other => panic!("expected binary, got {:?}", other),
            },
            other => panic!("unexpected effect: {:?}", other),
        }
    }
}
