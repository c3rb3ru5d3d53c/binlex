use super::reg;
use crate::irs::lir::executor::LirExecutorError;
use crate::irs::lir::{LirAbi, LirCpu};

pub fn i386(cpu: &LirCpu) -> Result<LirAbi, LirExecutorError> {
    Ok(LirAbi::new(
        "cdecl".to_string(),
        cpu.clone(),
        vec![
            crate::irs::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 4,
                bits: 32,
            },
            crate::irs::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 8,
                bits: 32,
            },
            crate::irs::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 12,
                bits: 32,
            },
            crate::irs::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 16,
                bits: 32,
            },
            crate::irs::lir::LirLocation::StackMemory {
                name: "stack".to_string(),
                offset: 20,
                bits: 32,
            },
            crate::irs::lir::LirLocation::StackMemory {
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
