use super::reg;
use crate::semantics::{SemanticAbi, SemanticCpu};
use crate::symbolic::Error;

pub fn arm64(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "sysv".to_string(),
        cpu.clone(),
        vec![
            reg("x0", 64),
            reg("x1", 64),
            reg("x2", 64),
            reg("x3", 64),
            reg("x4", 64),
            reg("x5", 64),
            reg("x6", 64),
            reg("x7", 64),
        ],
        vec![reg("x0", 64), reg("w0", 32)],
        Some(64),
        Vec::new(),
    ))
}

pub fn amd64(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "sysv".to_string(),
        cpu.clone(),
        vec![
            reg("rdi", 64),
            reg("rsi", 64),
            reg("rdx", 64),
            reg("rcx", 64),
            reg("r8", 64),
            reg("r9", 64),
        ],
        vec![reg("rax", 64), reg("eax", 32)],
        Some(64),
        Vec::new(),
    ))
}
