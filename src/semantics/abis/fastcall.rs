use super::reg;
use crate::semantics::{SemanticAbi, SemanticCpu};
use crate::symbolic::Error;

pub fn i386(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "fastcall".to_string(),
        cpu.clone(),
        vec![
            reg("ecx", 32),
            reg("edx", 32),
            crate::semantics::SemanticLocation::StackMemory {
                name: "stack".to_string(),
                offset: 4,
                bits: 32,
            },
            crate::semantics::SemanticLocation::StackMemory {
                name: "stack".to_string(),
                offset: 8,
                bits: 32,
            },
            crate::semantics::SemanticLocation::StackMemory {
                name: "stack".to_string(),
                offset: 12,
                bits: 32,
            },
            crate::semantics::SemanticLocation::StackMemory {
                name: "stack".to_string(),
                offset: 16,
                bits: 32,
            },
        ],
        vec![reg("eax", 32)],
        Some(32),
        Vec::new(),
    ))
}
