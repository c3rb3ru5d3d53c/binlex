use super::reg;
use crate::semantics::{SemanticAbi, SemanticAbiTrap, SemanticCpu, SemanticTrapKind};
use crate::symbolic::Error;

pub fn arm64(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "windows_syscall".to_string(),
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
                reg("x6", 64),
                reg("x7", 64),
            ],
            number_register: Some(reg("x8", 64)),
            result_registers: vec![reg("x0", 64), reg("w0", 32)],
            shadow_registers: Vec::new(),
        }],
    ))
}

pub fn amd64(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "windows_syscall".to_string(),
        cpu.clone(),
        Vec::new(),
        Vec::new(),
        None,
        vec![SemanticAbiTrap {
            kind: SemanticTrapKind::Syscall,
            argument_registers: vec![reg("rdx", 64), reg("r8", 64), reg("r9", 64)],
            number_register: Some(reg("rax", 64)),
            result_registers: vec![reg("rax", 64), reg("eax", 32)],
            shadow_registers: vec![reg("r10", 64), reg("rcx", 64)],
        }],
    ))
}

pub fn i386(cpu: &SemanticCpu) -> Result<SemanticAbi, Error> {
    Ok(SemanticAbi::new(
        "windows_syscall".to_string(),
        cpu.clone(),
        Vec::new(),
        Vec::new(),
        None,
        vec![
            SemanticAbiTrap {
                kind: SemanticTrapKind::Interrupt,
                argument_registers: vec![reg("edx", 32)],
                number_register: Some(reg("eax", 32)),
                result_registers: vec![reg("eax", 32)],
                shadow_registers: Vec::new(),
            },
            SemanticAbiTrap {
                kind: SemanticTrapKind::Named {
                    name: "x86.sysenter".to_string(),
                },
                argument_registers: vec![reg("ecx", 32), reg("edx", 32)],
                number_register: Some(reg("eax", 32)),
                result_registers: vec![reg("eax", 32)],
                shadow_registers: Vec::new(),
            },
        ],
    ))
}
