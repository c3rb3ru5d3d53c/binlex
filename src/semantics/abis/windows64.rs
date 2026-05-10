use super::reg;
use crate::semantics::{SemanticAbi, SemanticCpu};
use crate::symbolic::Error;

pub fn amd64(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "windows64".to_string(),
        cpu.clone(),
        vec![reg("rcx", 64), reg("rdx", 64), reg("r8", 64), reg("r9", 64)],
        vec![reg("rax", 64), reg("eax", 32)],
        Some(64),
        Vec::new(),
    ))
}
