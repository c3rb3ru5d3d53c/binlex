use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation, SemanticStatus,
    SemanticTerminator,
};
use std::io::Error;

pub fn validate_instruction_semantics(semantics: &InstructionSemantics) -> Result<(), Error> {
    match semantics.status {
        SemanticStatus::Complete if !semantics.diagnostics.is_empty() => {
            return Err(Error::other(
                "complete semantics must not carry diagnostics",
            ));
        }
        SemanticStatus::Partial if semantics.diagnostics.is_empty() => {
            return Err(Error::other(
                "partial semantics must include at least one diagnostic",
            ));
        }
        _ => {}
    }

    for temporary in &semantics.temporaries {
        if temporary.bits == 0 {
            return Err(Error::other(format!(
                "semantic temporary {} has zero width",
                temporary.id
            )));
        }
    }

    for effect in &semantics.effects {
        validate_effect(effect)?;
    }

    validate_terminator(&semantics.terminator)?;
    Ok(())
}

fn validate_effect(effect: &SemanticEffect) -> Result<(), Error> {
    match effect {
        SemanticEffect::Set { dst, expression } => {
            validate_location(dst)?;
            validate_expression(expression)?;
        }
        SemanticEffect::Store {
            space: _,
            addr,
            expression,
            bits,
        } => {
            if *bits == 0 {
                return Err(Error::other("semantic store has zero width"));
            }
            validate_expression(addr)?;
            validate_expression(expression)?;
        }
        SemanticEffect::MemorySet {
            addr,
            value,
            count,
            element_bits,
            decrement,
            ..
        } => {
            if *element_bits == 0 {
                return Err(Error::other("semantic memory-set has zero element width"));
            }
            validate_expression(addr)?;
            validate_expression(value)?;
            validate_expression(count)?;
            validate_expression(decrement)?;
        }
        SemanticEffect::MemoryCopy {
            src_addr,
            dst_addr,
            count,
            element_bits,
            decrement,
            ..
        } => {
            if *element_bits == 0 {
                return Err(Error::other("semantic memory-copy has zero element width"));
            }
            validate_expression(src_addr)?;
            validate_expression(dst_addr)?;
            validate_expression(count)?;
            validate_expression(decrement)?;
        }
        SemanticEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            bits,
            observed,
            ..
        } => {
            if *bits == 0 {
                return Err(Error::other("semantic atomic compare-exchange has zero width"));
            }
            validate_expression(addr)?;
            validate_expression(expected)?;
            validate_expression(desired)?;
            validate_location(observed)?;
        }
        SemanticEffect::Fence { .. } | SemanticEffect::Trap { .. } | SemanticEffect::Nop => {}
        SemanticEffect::Intrinsic { outputs, args, .. } => {
            for output in outputs {
                validate_location(output)?;
            }
            for arg in args {
                validate_expression(arg)?;
            }
        }
    }

    Ok(())
}

fn validate_terminator(terminator: &SemanticTerminator) -> Result<(), Error> {
    match terminator {
        SemanticTerminator::FallThrough
        | SemanticTerminator::Unreachable
        | SemanticTerminator::Trap => {}
        SemanticTerminator::Jump { target } => validate_expression(target)?,
        SemanticTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            validate_expression(condition)?;
            validate_expression(true_target)?;
            validate_expression(false_target)?;
        }
        SemanticTerminator::Call {
            target,
            return_target,
            ..
        } => {
            validate_expression(target)?;
            if let Some(return_target) = return_target {
                validate_expression(return_target)?;
            }
        }
        SemanticTerminator::Return { expression } => {
            if let Some(expression) = expression {
                validate_expression(expression)?;
            }
        }
    }

    Ok(())
}

fn validate_location(location: &SemanticLocation) -> Result<(), Error> {
    match location {
        SemanticLocation::Register { bits, .. }
        | SemanticLocation::Flag { bits, .. }
        | SemanticLocation::ProgramCounter { bits }
        | SemanticLocation::Temporary { bits, .. } => {
            if *bits == 0 {
                return Err(Error::other("semantic location has zero width"));
            }
        }
        SemanticLocation::Memory { addr, bits, .. } => {
            if *bits == 0 {
                return Err(Error::other("semantic memory location has zero width"));
            }
            validate_expression(addr)?;
        }
    }

    Ok(())
}

fn validate_expression(expression: &SemanticExpression) -> Result<(), Error> {
    if expression_bits(expression) == 0 {
        return Err(Error::other(format!(
            "semantic expression {:?} has zero width",
            expression.kind()
        )));
    }

    match expression {
        SemanticExpression::Const { .. }
        | SemanticExpression::Undefined { .. }
        | SemanticExpression::Poison { .. } => {}
        SemanticExpression::Read(location) => validate_location(location)?,
        SemanticExpression::Load { addr, .. } => validate_expression(addr)?,
        SemanticExpression::Unary { arg, .. } => validate_expression(arg)?,
        SemanticExpression::Binary { left, right, .. }
        | SemanticExpression::Compare { left, right, .. } => {
            validate_expression(left)?;
            validate_expression(right)?;
        }
        SemanticExpression::Cast { arg, .. } | SemanticExpression::Extract { arg, .. } => {
            validate_expression(arg)?;
        }
        SemanticExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            validate_expression(condition)?;
            validate_expression(when_true)?;
            validate_expression(when_false)?;
        }
        SemanticExpression::Concat { parts, .. }
        | SemanticExpression::Intrinsic { args: parts, .. } => {
            for part in parts {
                validate_expression(part)?;
            }
        }
    }

    Ok(())
}

fn expression_bits(expression: &SemanticExpression) -> u16 {
    match expression {
        SemanticExpression::Const { bits, .. }
        | SemanticExpression::Load { bits, .. }
        | SemanticExpression::Unary { bits, .. }
        | SemanticExpression::Binary { bits, .. }
        | SemanticExpression::Cast { bits, .. }
        | SemanticExpression::Compare { bits, .. }
        | SemanticExpression::Select { bits, .. }
        | SemanticExpression::Extract { bits, .. }
        | SemanticExpression::Concat { bits, .. }
        | SemanticExpression::Undefined { bits }
        | SemanticExpression::Poison { bits }
        | SemanticExpression::Intrinsic { bits, .. } => *bits,
        SemanticExpression::Read(location) => match location.as_ref() {
            SemanticLocation::Register { bits, .. }
            | SemanticLocation::Flag { bits, .. }
            | SemanticLocation::ProgramCounter { bits }
            | SemanticLocation::Temporary { bits, .. }
            | SemanticLocation::Memory { bits, .. } => *bits,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::validate_instruction_semantics;
    use crate::semantics::{
        InstructionSemantics, SemanticDiagnostic, SemanticDiagnosticKind, SemanticEffect,
        SemanticExpression, SemanticStatus, SemanticTerminator,
    };

    #[test]
    fn rejects_zero_width_store() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Store {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: SemanticExpression::Const { value: 0, bits: 64 },
                expression: SemanticExpression::Const { value: 0, bits: 64 },
                bits: 0,
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        assert!(validate_instruction_semantics(&semantics).is_err());
    }

    #[test]
    fn rejects_complete_semantics_with_diagnostics() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::FallThrough,
            diagnostics: vec![SemanticDiagnostic {
                kind: SemanticDiagnosticKind::PartialFlags,
                message: "flags are modeled conservatively".to_string(),
            }],
        };

        assert!(validate_instruction_semantics(&semantics).is_err());
    }

    #[test]
    fn rejects_partial_semantics_without_diagnostics() {
        let semantics = InstructionSemantics {
            version: 1,
            status: SemanticStatus::Partial,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        assert!(validate_instruction_semantics(&semantics).is_err());
    }
}
