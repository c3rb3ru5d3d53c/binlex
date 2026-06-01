use super::reg;
use crate::ir::lir::{LirAbi, LirCpu};
use crate::symbolic::Error;

pub fn amd64(cpu: &LirCpu) -> Result<LirAbi, Error> {
    let mut arguments = vec![reg("rcx", 64), reg("rdx", 64), reg("r8", 64), reg("r9", 64)];
    arguments.extend(
        (0..8).map(|index| crate::ir::lir::LirLocation::StackMemory {
            name: "stack".to_string(),
            offset: 0x20 + (index * 8),
            bits: 64,
        }),
    );

    Ok(LirAbi::new(
        "windows64".to_string(),
        cpu.clone(),
        arguments,
        vec![reg("rax", 64), reg("eax", 32)],
        Some(64),
        Vec::new(),
    ))
}
