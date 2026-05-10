use super::{
    SemanticCpu, SemanticCpuAlias, SemanticCpuEndian, SemanticCpuKind, SemanticCpuProgramCounter,
    SemanticCpuRegister, SemanticMemory,
};
use crate::symbolic::Error;

pub fn build() -> Result<SemanticCpu, Error> {
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
    SemanticCpu::builtin(
        SemanticCpuKind::Arm64,
        "arm64",
        64,
        SemanticCpuEndian::Little,
        registers,
        aliases,
        Some(SemanticCpuProgramCounter::new("pc", 64)),
        vec![
            SemanticMemory::stack("stack"),
            SemanticMemory::addressed("default", 64, SemanticCpuEndian::Little),
        ],
    )
}
