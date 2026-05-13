use super::reg;
use crate::ir::lir::{LirAbi, LirCpu};
use crate::symbolic::Error;

pub fn i386(cpu: &LirCpu) -> Result<LirAbi, Error> {
    Ok(LirAbi::new(
        "stdcall".to_string(),
        cpu.clone(),
        vec![
            crate::ir::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 4,
                bits: 32,
            },
            crate::ir::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 8,
                bits: 32,
            },
            crate::ir::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 12,
                bits: 32,
            },
            crate::ir::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 16,
                bits: 32,
            },
            crate::ir::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 20,
                bits: 32,
            },
            crate::ir::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 24,
                bits: 32,
            },
        ],
        vec![reg("eax", 32)],
        Some(32),
        Vec::new(),
    ))
}
