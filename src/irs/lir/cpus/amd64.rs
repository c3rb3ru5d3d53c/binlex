use super::{
    LirCpu, LirCpuAlias, LirCpuEndian, LirCpuKind, LirCpuProgramCounter, LirCpuRegister, LirMemory,
};
use crate::irs::lir::executor::LirExecutorError;

pub fn build() -> Result<LirCpu, LirExecutorError> {
    let mut registers = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    ]
    .into_iter()
    .map(|name| LirCpuRegister::new(name, 64))
    .collect::<Vec<_>>();
    registers.extend(
        ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
            .into_iter()
            .map(|name| LirCpuRegister::new(name, 64)),
    );
    let mut aliases = vec![
        LirCpuAlias::zero_extend("eax", "rax", 0, 32),
        LirCpuAlias::new("ax", "rax", 0, 16),
        LirCpuAlias::new("al", "rax", 0, 8),
        LirCpuAlias::new("ah", "rax", 8, 8),
        LirCpuAlias::zero_extend("ebx", "rbx", 0, 32),
        LirCpuAlias::new("bx", "rbx", 0, 16),
        LirCpuAlias::new("bl", "rbx", 0, 8),
        LirCpuAlias::new("bh", "rbx", 8, 8),
        LirCpuAlias::zero_extend("ecx", "rcx", 0, 32),
        LirCpuAlias::new("cx", "rcx", 0, 16),
        LirCpuAlias::new("cl", "rcx", 0, 8),
        LirCpuAlias::new("ch", "rcx", 8, 8),
        LirCpuAlias::zero_extend("edx", "rdx", 0, 32),
        LirCpuAlias::new("dx", "rdx", 0, 16),
        LirCpuAlias::new("dl", "rdx", 0, 8),
        LirCpuAlias::new("dh", "rdx", 8, 8),
        LirCpuAlias::zero_extend("esi", "rsi", 0, 32),
        LirCpuAlias::new("si", "rsi", 0, 16),
        LirCpuAlias::new("sil", "rsi", 0, 8),
        LirCpuAlias::zero_extend("edi", "rdi", 0, 32),
        LirCpuAlias::new("di", "rdi", 0, 16),
        LirCpuAlias::new("dil", "rdi", 0, 8),
        LirCpuAlias::zero_extend("ebp", "rbp", 0, 32),
        LirCpuAlias::new("bp", "rbp", 0, 16),
        LirCpuAlias::new("bpl", "rbp", 0, 8),
        LirCpuAlias::zero_extend("esp", "rsp", 0, 32),
        LirCpuAlias::new("sp", "rsp", 0, 16),
        LirCpuAlias::new("spl", "rsp", 0, 8),
        LirCpuAlias::zero_extend("eip", "rip", 0, 32),
        LirCpuAlias::new("ip", "rip", 0, 16),
    ];
    for index in 8..=15 {
        let parent = format!("r{index}");
        aliases.push(LirCpuAlias::zero_extend(
            format!("r{index}d"),
            parent.clone(),
            0,
            32,
        ));
        aliases.push(LirCpuAlias::new(
            format!("r{index}w"),
            parent.clone(),
            0,
            16,
        ));
        aliases.push(LirCpuAlias::new(format!("r{index}b"), parent, 0, 8));
    }
    LirCpu::builtin(
        LirCpuKind::Amd64,
        "amd64",
        64,
        LirCpuEndian::Little,
        registers,
        aliases,
        Some(LirCpuProgramCounter::new("rip", 64)),
        vec![
            LirMemory::stack("stack"),
            LirMemory::addressed("default", 64, LirCpuEndian::Little),
        ],
    )
}
