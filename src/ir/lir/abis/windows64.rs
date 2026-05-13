use super::reg;
use crate::ir::lir::{LirAbi, LirCpu};
use crate::symbolic::Error;

pub fn amd64(cpu: &LirCpu) -> Result<LirAbi, Error> {
    Ok(LirAbi::new(
        "windows64".to_string(),
        cpu.clone(),
        vec![reg("rcx", 64), reg("rdx", 64), reg("r8", 64), reg("r9", 64)],
        vec![reg("rax", 64), reg("eax", 32)],
        Some(64),
        Vec::new(),
    ))
}
