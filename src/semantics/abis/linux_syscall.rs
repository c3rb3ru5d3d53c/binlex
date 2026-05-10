use super::reg;
use crate::semantics::{SemanticAbi, SemanticAbiTrap, SemanticCpu, SemanticTrapKind};
use crate::symbolic::Error;

pub fn arm64(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "linux_syscall".to_string(),
        cpu.clone(),
        Vec::new(),
        Vec::new(),
        None,
        vec![SemanticAbiTrap {
            kind: SemanticTrapKind::Syscall,
            argument_registers: vec![
                reg("x0", 64),
                reg("x1", 64),
                reg("x2", 64),
                reg("x3", 64),
                reg("x4", 64),
                reg("x5", 64),
            ],
            number_register: Some(reg("x8", 64)),
            result_registers: vec![reg("x0", 64), reg("w0", 32)],
            shadow_registers: Vec::new(),
        }],
    ))
}

pub fn amd64(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "linux_syscall".to_string(),
        cpu.clone(),
        Vec::new(),
        Vec::new(),
        None,
        vec![SemanticAbiTrap {
            kind: SemanticTrapKind::Syscall,
            argument_registers: vec![
                reg("rdi", 64),
                reg("rsi", 64),
                reg("rdx", 64),
                reg("r10", 64),
                reg("r8", 64),
                reg("r9", 64),
            ],
            number_register: Some(reg("rax", 64)),
            result_registers: vec![reg("rax", 64), reg("eax", 32)],
            shadow_registers: Vec::new(),
        }],
    ))
}

pub fn i386(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "linux_syscall".to_string(),
        cpu.clone(),
        Vec::new(),
        Vec::new(),
        None,
        vec![
            SemanticAbiTrap {
                kind: SemanticTrapKind::Interrupt,
                argument_registers: vec![
                    reg("ebx", 32),
                    reg("ecx", 32),
                    reg("edx", 32),
                    reg("esi", 32),
                    reg("edi", 32),
                    reg("ebp", 32),
                ],
                number_register: Some(reg("eax", 32)),
                result_registers: vec![reg("eax", 32)],
                shadow_registers: Vec::new(),
            },
            SemanticAbiTrap {
                kind: SemanticTrapKind::Named {
                    name: "x86.sysenter".to_string(),
                },
                argument_registers: vec![
                    reg("ebx", 32),
                    reg("ecx", 32),
                    reg("edx", 32),
                    reg("esi", 32),
                    reg("edi", 32),
                    reg("ebp", 32),
                ],
                number_register: Some(reg("eax", 32)),
                result_registers: vec![reg("eax", 32)],
                shadow_registers: Vec::new(),
            },
        ],
    ))
}
