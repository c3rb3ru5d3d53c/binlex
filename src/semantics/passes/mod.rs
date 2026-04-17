use crate::semantics::InstructionSemantics;
use std::io::Error;

pub mod normalize;
pub mod validate;

pub fn validate_instruction_semantics(semantics: &InstructionSemantics) -> Result<(), Error> {
    validate::validate_instruction_semantics(semantics)
}

pub fn normalize_instruction_semantics(semantics: &InstructionSemantics) -> InstructionSemantics {
    normalize::normalize_instruction_semantics(semantics)
}
