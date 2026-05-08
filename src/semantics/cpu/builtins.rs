use super::{
    SemanticCpu, SemanticCpuAlias, SemanticCpuEndian, SemanticCpuProgramCounter,
    SemanticCpuRegister, SemanticMemory,
};
use crate::symbolic::Error;

pub fn i386() -> Result<SemanticCpu, Error> {
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
    SemanticCpu::new(
        "i386",
        32,
        SemanticCpuEndian::Little,
        registers,
        aliases,
        Some(SemanticCpuProgramCounter::new("eip", 32)),
        vec![SemanticMemory::addressed(
            "default",
            32,
            SemanticCpuEndian::Little,
        )],
    )
}

pub fn amd64() -> Result<SemanticCpu, Error> {
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
    SemanticCpu::new(
        "amd64",
        64,
        SemanticCpuEndian::Little,
        registers,
        aliases,
        Some(SemanticCpuProgramCounter::new("rip", 64)),
        vec![SemanticMemory::addressed(
            "default",
            64,
            SemanticCpuEndian::Little,
        )],
    )
}

pub fn arm64() -> Result<SemanticCpu, Error> {
    let mut registers = (0..=30)
        .map(|index| SemanticCpuRegister::new(format!("x{index}"), 64))
        .collect::<Vec<_>>();
    registers.push(SemanticCpuRegister::new("sp", 64));
    registers.push(SemanticCpuRegister::new("pc", 64));
    for index in 0..=31 {
        registers.push(SemanticCpuRegister::new(format!("v{index}"), 128));
    }
    let mut aliases = (0..=30)
        .map(|index| SemanticCpuAlias::zero_extend(format!("w{index}"), format!("x{index}"), 0, 32))
        .collect::<Vec<_>>();
    aliases.push(SemanticCpuAlias::zero_extend("wsp", "sp", 0, 32));
    for index in 0..=31 {
        let parent = format!("v{index}");
        aliases.push(SemanticCpuAlias::new(
            format!("b{index}"),
            parent.clone(),
            0,
            8,
        ));
        aliases.push(SemanticCpuAlias::new(
            format!("h{index}"),
            parent.clone(),
            0,
            16,
        ));
        aliases.push(SemanticCpuAlias::new(
            format!("s{index}"),
            parent.clone(),
            0,
            32,
        ));
        aliases.push(SemanticCpuAlias::new(
            format!("d{index}"),
            parent.clone(),
            0,
            64,
        ));
        aliases.push(SemanticCpuAlias::new(format!("q{index}"), parent, 0, 128));
    }
    SemanticCpu::new(
        "arm64",
        64,
        SemanticCpuEndian::Little,
        registers,
        aliases,
        Some(SemanticCpuProgramCounter::new("pc", 64)),
        vec![SemanticMemory::addressed(
            "default",
            64,
            SemanticCpuEndian::Little,
        )],
    )
}

pub fn cil() -> Result<SemanticCpu, Error> {
    SemanticCpu::new(
        "cil",
        64,
        SemanticCpuEndian::Little,
        vec![SemanticCpuRegister::new("pc", 64)],
        Vec::new(),
        Some(SemanticCpuProgramCounter::new("pc", 64)),
        vec![
            SemanticMemory::stack("evaluation_stack"),
            SemanticMemory::indexed("locals"),
            SemanticMemory::addressed("heap", 64, SemanticCpuEndian::Little),
        ],
    )
}
