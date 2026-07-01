use crate::irs::lir::{LirEffect, LirExpression, LirInstruction, LirLocation, LirTerminator};
use std::io::Error;

pub fn validate_instruction_lir(lir: &LirInstruction) -> Result<(), Error> {
    for effect in &lir.effects {
        validate_effect(effect)?;
    }

    validate_terminator(&lir.terminator)?;
    Ok(())
}

fn validate_effect(effect: &LirEffect) -> Result<(), Error> {
    match effect {
        LirEffect::Phi { dst, sources } => {
            validate_location(dst)?;
            if sources.is_empty() {
                return Err(Error::other("lir phi has no sources"));
            }
            for source in sources {
                validate_expression(&source.value)?;
            }
        }
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
                return Err(Error::other("lir store has zero width"));
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
                return Err(Error::other("lir memory-set has zero element width"));
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
                return Err(Error::other("lir memory-copy has zero element width"));
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
                return Err(Error::other("lir atomic compare-exchange has zero width"));
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
                return Err(Error::other("lir property write has zero width"));
            }
            if name.trim().is_empty() {
                return Err(Error::other("lir property write has empty name"));
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
                return Err(Error::other("lir element write has zero width"));
            }
            validate_expression(reference)?;
            validate_expression(index)?;
            validate_expression(expression)?;
        }
        LirEffect::Push { stack, expression } => {
            if stack.trim().is_empty() {
                return Err(Error::other("lir push has empty stack name"));
            }
            validate_expression(expression)?;
        }
        LirEffect::Pop { stack, dst } => {
            if stack.trim().is_empty() {
                return Err(Error::other("lir pop has empty stack name"));
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
                return Err(Error::other("lir location has zero width"));
            }
        }
        LirLocation::Memory { addr, bits, .. } => {
            if *bits == 0 {
                return Err(Error::other("lir memory location has zero width"));
            }
            validate_expression(addr)?;
        }
        LirLocation::IndexedMemory { index, bits, .. } => {
            if *bits == 0 {
                return Err(Error::other("lir indexed memory location has zero width"));
            }
            validate_expression(index)?;
        }
    }

    Ok(())
}

fn validate_expression(expression: &LirExpression) -> Result<(), Error> {
    if expression_bits(expression) == 0 {
        return Err(Error::other(format!(
            "lir expression {:?} has zero width",
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
                return Err(Error::other("lir function expression has empty name"));
            }
        }
        LirExpression::DataAddress { name, .. } => {
            if name.trim().is_empty() {
                return Err(Error::other("lir data_address expression has empty name"));
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
                return Err(Error::other("lir property read has empty name"));
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
    use crate::irs::lir::{LirEffect, LirExpression, LirInstruction, LirStatus, LirTerminator};

    #[test]
    fn rejects_zero_width_store() {
        let lir = LirInstruction {
            address: None,
            status: LirStatus::Complete,
            effects: vec![LirEffect::Store {
                space: crate::irs::lir::LirAddressSpace::Default,
                addr: LirExpression::Const { value: 0, bits: 64 },
                expression: LirExpression::Const { value: 0, bits: 64 },
                bits: 0,
            }],
            terminator: LirTerminator::FallThrough,
        };

        assert!(validate_instruction_lir(&lir).is_err());
    }
}
