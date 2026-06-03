use crate::ir::lir::{Lir, LirEffect, LirExpression, LirLocation, LirStatus, LirTerminator};
use std::io::Error;

pub fn validate_instruction_lir(semantics: &Lir) -> Result<(), Error> {
    match semantics.status {
        LirStatus::Complete if !semantics.diagnostics.is_empty() => {
            return Err(Error::other(
                "complete semantics must not carry diagnostics",
            ));
        }
        LirStatus::Partial if semantics.diagnostics.is_empty() => {
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

fn validate_effect(effect: &LirEffect) -> Result<(), Error> {
    match effect {
        LirEffect::Set { dst, expression } => {
            validate_location(dst)?;
            validate_expression(expression)?;
        }
        LirEffect::Store {
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
        LirEffect::MemorySet {
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
        LirEffect::MemoryCopy {
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
        LirEffect::AtomicCmpXchg {
            addr,
            expected,
            desired,
            bits,
            observed,
            ..
        } => {
            if *bits == 0 {
                return Err(Error::other(
                    "semantic atomic compare-exchange has zero width",
                ));
            }
            validate_expression(addr)?;
            validate_expression(expected)?;
            validate_expression(desired)?;
            validate_location(observed)?;
        }
        LirEffect::WriteProperty {
            reference,
            name,
            expression,
            bits,
        } => {
            if *bits == 0 {
                return Err(Error::other("semantic property write has zero width"));
            }
            if name.trim().is_empty() {
                return Err(Error::other("semantic property write has empty name"));
            }
            validate_expression(reference)?;
            validate_expression(expression)?;
        }
        LirEffect::WriteElement {
            reference,
            index,
            expression,
            bits,
        } => {
            if *bits == 0 {
                return Err(Error::other("semantic element write has zero width"));
            }
            validate_expression(reference)?;
            validate_expression(index)?;
            validate_expression(expression)?;
        }
        LirEffect::Push { stack, expression } => {
            if stack.trim().is_empty() {
                return Err(Error::other("semantic push has empty stack name"));
            }
            validate_expression(expression)?;
        }
        LirEffect::Pop { stack, dst } => {
            if stack.trim().is_empty() {
                return Err(Error::other("semantic pop has empty stack name"));
            }
            validate_location(dst)?;
        }
        LirEffect::Fence { .. } | LirEffect::Trap { .. } | LirEffect::Nop => {}
        LirEffect::Intrinsic { outputs, args, .. } => {
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

fn validate_terminator(terminator: &LirTerminator) -> Result<(), Error> {
    match terminator {
        LirTerminator::FallThrough | LirTerminator::Unreachable | LirTerminator::Trap => {}
        LirTerminator::Jump { target } => validate_expression(target)?,
        LirTerminator::Branch {
            condition,
            true_target,
            false_target,
        } => {
            validate_expression(condition)?;
            validate_expression(true_target)?;
            validate_expression(false_target)?;
        }
        LirTerminator::Call {
            target,
            return_target,
            ..
        } => {
            validate_expression(target)?;
            if let Some(return_target) = return_target {
                validate_expression(return_target)?;
            }
        }
        LirTerminator::Return { expression } => {
            if let Some(expression) = expression {
                validate_expression(expression)?;
            }
        }
    }

    Ok(())
}

fn validate_location(location: &LirLocation) -> Result<(), Error> {
    match location {
        LirLocation::Register { bits, .. }
        | LirLocation::Flag { bits, .. }
        | LirLocation::ProgramCounter { bits }
        | LirLocation::Temporary { bits, .. }
        | LirLocation::StackMemory { bits, .. } => {
            if *bits == 0 {
                return Err(Error::other("semantic location has zero width"));
            }
        }
        LirLocation::Memory { addr, bits, .. } => {
            if *bits == 0 {
                return Err(Error::other("semantic memory location has zero width"));
            }
            validate_expression(addr)?;
        }
        LirLocation::IndexedMemory { index, bits, .. } => {
            if *bits == 0 {
                return Err(Error::other(
                    "semantic indexed memory location has zero width",
                ));
            }
            validate_expression(index)?;
        }
    }

    Ok(())
}

fn validate_expression(expression: &LirExpression) -> Result<(), Error> {
    if expression_bits(expression) == 0 {
        return Err(Error::other(format!(
            "semantic expression {:?} has zero width",
            expression.kind()
        )));
    }

    match expression {
        LirExpression::Const { .. }
        | LirExpression::Undefined { .. }
        | LirExpression::Poison { .. }
        | LirExpression::Null { .. }
        | LirExpression::Allocate { .. } => {}
        LirExpression::Function { name, .. } => {
            if name.trim().is_empty() {
                return Err(Error::other("semantic function expression has empty name"));
            }
        }
        LirExpression::DataAddress { name, .. } => {
            if name.trim().is_empty() {
                return Err(Error::other(
                    "semantic data_address expression has empty name",
                ));
            }
        }
        LirExpression::AddressOf { location, .. } => validate_location(location)?,
        LirExpression::Read(location) => validate_location(location)?,
        LirExpression::Load { addr, .. } => validate_expression(addr)?,
        LirExpression::Unary { arg, .. } => validate_expression(arg)?,
        LirExpression::Binary { left, right, .. } | LirExpression::Compare { left, right, .. } => {
            validate_expression(left)?;
            validate_expression(right)?;
        }
        LirExpression::Cast { arg, .. } | LirExpression::Extract { arg, .. } => {
            validate_expression(arg)?;
        }
        LirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            validate_expression(condition)?;
            validate_expression(when_true)?;
            validate_expression(when_false)?;
        }
        LirExpression::Concat { parts, .. } | LirExpression::Intrinsic { args: parts, .. } => {
            for part in parts {
                validate_expression(part)?;
            }
        }
        LirExpression::ReadProperty {
            reference, name, ..
        } => {
            if name.trim().is_empty() {
                return Err(Error::other("semantic property read has empty name"));
            }
            validate_expression(reference)?;
        }
        LirExpression::ReadElement {
            reference, index, ..
        } => {
            validate_expression(reference)?;
            validate_expression(index)?;
        }
    }

    Ok(())
}

fn expression_bits(expression: &LirExpression) -> u16 {
    match expression {
        LirExpression::Const { bits, .. }
        | LirExpression::Function { bits, .. }
        | LirExpression::DataAddress { bits, .. }
        | LirExpression::AddressOf { bits, .. }
        | LirExpression::Load { bits, .. }
        | LirExpression::Unary { bits, .. }
        | LirExpression::Binary { bits, .. }
        | LirExpression::Cast { bits, .. }
        | LirExpression::Compare { bits, .. }
        | LirExpression::Select { bits, .. }
        | LirExpression::Extract { bits, .. }
        | LirExpression::Concat { bits, .. }
        | LirExpression::Undefined { bits }
        | LirExpression::Poison { bits }
        | LirExpression::Intrinsic { bits, .. }
        | LirExpression::Null { bits }
        | LirExpression::Allocate { bits, .. }
        | LirExpression::ReadProperty { bits, .. }
        | LirExpression::ReadElement { bits, .. } => *bits,
        LirExpression::Read(location) => match location.as_ref() {
            LirLocation::Register { bits, .. }
            | LirLocation::Flag { bits, .. }
            | LirLocation::ProgramCounter { bits }
            | LirLocation::Temporary { bits, .. }
            | LirLocation::Memory { bits, .. }
            | LirLocation::IndexedMemory { bits, .. }
            | LirLocation::StackMemory { bits, .. } => *bits,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::validate_instruction_lir;
    use crate::ir::lir::{
        Lir, LirDiagnostic, LirDiagnosticKind, LirEffect, LirExpression, LirStatus, LirTerminator,
    };

    #[test]
    fn rejects_zero_width_store() {
        let semantics = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Store {
                space: crate::ir::lir::LirAddressSpace::Default,
                addr: LirExpression::Const { value: 0, bits: 64 },
                expression: LirExpression::Const { value: 0, bits: 64 },
                bits: 0,
            }],
            terminator: LirTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        assert!(validate_instruction_lir(&semantics).is_err());
    }

    #[test]
    fn rejects_complete_semantics_with_diagnostics() {
        let semantics = Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
            diagnostics: vec![LirDiagnostic {
                kind: LirDiagnosticKind::PartialFlags,
                message: "flags are modeled conservatively".to_string(),
            }],
        };

        assert!(validate_instruction_lir(&semantics).is_err());
    }

    #[test]
    fn rejects_partial_semantics_without_diagnostics() {
        let semantics = Lir {
            version: 1,
            status: LirStatus::Partial,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
            diagnostics: Vec::new(),
        };

        assert!(validate_instruction_lir(&semantics).is_err());
    }
}
