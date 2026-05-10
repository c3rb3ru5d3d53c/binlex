use super::{
    SemanticCpu, SemanticCpuAlias, SemanticCpuEndian, SemanticCpuKind, SemanticCpuProgramCounter,
    SemanticCpuRegister, SemanticMemory,
};
use crate::symbolic::Error;

pub fn build() -> Result<SemanticCpu, Error> {
    let registers = [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
    ]
    .into_iter()
    .map(|name| SemanticCpuRegister::new(name, 32))
    .collect();
    let aliases = vec![
        SemanticCpuAlias::new("ax", "eax", 0, 16),
        SemanticCpuAlias::new("al", "eax", 0, 8),
        SemanticCpuAlias::new("ah", "eax", 8, 8),
        SemanticCpuAlias::new("bx", "ebx", 0, 16),
        SemanticCpuAlias::new("bl", "ebx", 0, 8),
        SemanticCpuAlias::new("bh", "ebx", 8, 8),
        SemanticCpuAlias::new("cx", "ecx", 0, 16),
        SemanticCpuAlias::new("cl", "ecx", 0, 8),
        SemanticCpuAlias::new("ch", "ecx", 8, 8),
        SemanticCpuAlias::new("dx", "edx", 0, 16),
        SemanticCpuAlias::new("dl", "edx", 0, 8),
        SemanticCpuAlias::new("dh", "edx", 8, 8),
        SemanticCpuAlias::new("si", "esi", 0, 16),
        SemanticCpuAlias::new("di", "edi", 0, 16),
        SemanticCpuAlias::new("bp", "ebp", 0, 16),
        SemanticCpuAlias::new("sp", "esp", 0, 16),
        SemanticCpuAlias::new("ip", "eip", 0, 16),
    ];
    SemanticCpu::builtin(
        SemanticCpuKind::I386,
        "i386",
        32,
        SemanticCpuEndian::Little,
        registers,
        aliases,
        Some(SemanticCpuProgramCounter::new("eip", 32)),
        vec![
            SemanticMemory::stack("stack"),
            SemanticMemory::addressed("default", 32, SemanticCpuEndian::Little),
        ],
    )
}
