use super::{
    LirCpu, LirCpuAlias, LirCpuEndian, LirCpuKind, LirCpuProgramCounter, LirCpuRegister, LirMemory,
};
use crate::ir::lir::executor::LirExecutorError;

pub fn build() -> Result<LirCpu, LirExecutorError> {
    let registers = [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
    ]
    .into_iter()
    .map(|name| LirCpuRegister::new(name, 32))
    .collect();
    let aliases = vec![
        LirCpuAlias::new("ax", "eax", 0, 16),
        LirCpuAlias::new("al", "eax", 0, 8),
        LirCpuAlias::new("ah", "eax", 8, 8),
        LirCpuAlias::new("bx", "ebx", 0, 16),
        LirCpuAlias::new("bl", "ebx", 0, 8),
        LirCpuAlias::new("bh", "ebx", 8, 8),
        LirCpuAlias::new("cx", "ecx", 0, 16),
        LirCpuAlias::new("cl", "ecx", 0, 8),
        LirCpuAlias::new("ch", "ecx", 8, 8),
        LirCpuAlias::new("dx", "edx", 0, 16),
        LirCpuAlias::new("dl", "edx", 0, 8),
        LirCpuAlias::new("dh", "edx", 8, 8),
        LirCpuAlias::new("si", "esi", 0, 16),
        LirCpuAlias::new("di", "edi", 0, 16),
        LirCpuAlias::new("bp", "ebp", 0, 16),
        LirCpuAlias::new("sp", "esp", 0, 16),
        LirCpuAlias::new("ip", "eip", 0, 16),
    ];
    LirCpu::builtin(
        LirCpuKind::I386,
        "i386",
        32,
        LirCpuEndian::Little,
        registers,
        aliases,
        Some(LirCpuProgramCounter::new("eip", 32)),
        vec![
            LirMemory::stack("stack"),
            LirMemory::addressed("default", 32, LirCpuEndian::Little),
        ],
    )
}
