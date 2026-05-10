use super::{
    SemanticCpu, SemanticCpuAlias, SemanticCpuEndian, SemanticCpuKind, SemanticCpuProgramCounter,
    SemanticCpuRegister, SemanticMemory,
};
use crate::symbolic::Error;

pub fn build() -> Result<SemanticCpu, Error> {
    let mut registers = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    ]
    .into_iter()
    .map(|name| SemanticCpuRegister::new(name, 64))
    .collect::<Vec<_>>();
    registers.extend(
        ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
            .into_iter()
            .map(|name| SemanticCpuRegister::new(name, 64)),
    );
    let mut aliases = vec![
        SemanticCpuAlias::zero_extend("eax", "rax", 0, 32),
        SemanticCpuAlias::new("ax", "rax", 0, 16),
        SemanticCpuAlias::new("al", "rax", 0, 8),
        SemanticCpuAlias::new("ah", "rax", 8, 8),
        SemanticCpuAlias::zero_extend("ebx", "rbx", 0, 32),
        SemanticCpuAlias::new("bx", "rbx", 0, 16),
        SemanticCpuAlias::new("bl", "rbx", 0, 8),
        SemanticCpuAlias::new("bh", "rbx", 8, 8),
        SemanticCpuAlias::zero_extend("ecx", "rcx", 0, 32),
        SemanticCpuAlias::new("cx", "rcx", 0, 16),
        SemanticCpuAlias::new("cl", "rcx", 0, 8),
        SemanticCpuAlias::new("ch", "rcx", 8, 8),
        SemanticCpuAlias::zero_extend("edx", "rdx", 0, 32),
        SemanticCpuAlias::new("dx", "rdx", 0, 16),
        SemanticCpuAlias::new("dl", "rdx", 0, 8),
        SemanticCpuAlias::new("dh", "rdx", 8, 8),
        SemanticCpuAlias::zero_extend("esi", "rsi", 0, 32),
        SemanticCpuAlias::new("si", "rsi", 0, 16),
        SemanticCpuAlias::new("sil", "rsi", 0, 8),
        SemanticCpuAlias::zero_extend("edi", "rdi", 0, 32),
        SemanticCpuAlias::new("di", "rdi", 0, 16),
        SemanticCpuAlias::new("dil", "rdi", 0, 8),
        SemanticCpuAlias::zero_extend("ebp", "rbp", 0, 32),
        SemanticCpuAlias::new("bp", "rbp", 0, 16),
        SemanticCpuAlias::new("bpl", "rbp", 0, 8),
        SemanticCpuAlias::zero_extend("esp", "rsp", 0, 32),
        SemanticCpuAlias::new("sp", "rsp", 0, 16),
        SemanticCpuAlias::new("spl", "rsp", 0, 8),
        SemanticCpuAlias::zero_extend("eip", "rip", 0, 32),
        SemanticCpuAlias::new("ip", "rip", 0, 16),
    ];
    for index in 8..=15 {
        let parent = format!("r{index}");
        aliases.push(SemanticCpuAlias::zero_extend(
            format!("r{index}d"),
            parent.clone(),
            0,
            32,
        ));
        aliases.push(SemanticCpuAlias::new(
            format!("r{index}w"),
            parent.clone(),
            0,
            16,
        ));
        aliases.push(SemanticCpuAlias::new(format!("r{index}b"), parent, 0, 8));
    }
    SemanticCpu::builtin(
        SemanticCpuKind::Amd64,
        "amd64",
        64,
        SemanticCpuEndian::Little,
        registers,
        aliases,
        Some(SemanticCpuProgramCounter::new("rip", 64)),
        vec![
            SemanticMemory::stack("stack"),
            SemanticMemory::addressed("default", 64, SemanticCpuEndian::Little),
        ],
    )
}
