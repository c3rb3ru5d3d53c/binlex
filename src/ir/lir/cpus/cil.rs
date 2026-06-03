use super::{LirCpu, LirCpuEndian, LirCpuKind, LirCpuProgramCounter, LirCpuRegister, LirMemory};
use crate::ir::lir::executor::LirExecutorError;

pub fn build() -> Result<LirCpu, LirExecutorError> {
    LirCpu::builtin(
        LirCpuKind::Cil,
        "cil",
        64,
        LirCpuEndian::Little,
        vec![LirCpuRegister::new("pc", 64)],
        Vec::new(),
        Some(LirCpuProgramCounter::new("pc", 64)),
        vec![
            LirMemory::stack("evaluation_stack"),
            LirMemory::indexed("locals"),
            LirMemory::addressed("heap", 64, LirCpuEndian::Little),
        ],
    )
}
