use super::{
    LirCpu, LirCpuAlias, LirCpuEndian, LirCpuKind, LirCpuProgramCounter, LirCpuRegister, LirMemory,
};
use crate::irs::lir::executor::LirExecutorError;

pub fn build() -> Result<LirCpu, LirExecutorError> {
    let mut registers = (0..=30)
        .map(|index| LirCpuRegister::new(format!("x{index}"), 64))
        .collect::<Vec<_>>();
    registers.push(LirCpuRegister::new("sp", 64));
    registers.push(LirCpuRegister::new("pc", 64));
    for index in 0..=31 {
        registers.push(LirCpuRegister::new(format!("v{index}"), 128));
    }
    let mut aliases = (0..=30)
        .map(|index| LirCpuAlias::zero_extend(format!("w{index}"), format!("x{index}"), 0, 32))
        .collect::<Vec<_>>();
    aliases.push(LirCpuAlias::zero_extend("wsp", "sp", 0, 32));
    for index in 0..=31 {
        let parent = format!("v{index}");
        aliases.push(LirCpuAlias::new(format!("b{index}"), parent.clone(), 0, 8));
        aliases.push(LirCpuAlias::new(format!("h{index}"), parent.clone(), 0, 16));
        aliases.push(LirCpuAlias::new(format!("s{index}"), parent.clone(), 0, 32));
        aliases.push(LirCpuAlias::new(format!("d{index}"), parent.clone(), 0, 64));
        aliases.push(LirCpuAlias::new(format!("q{index}"), parent, 0, 128));
    }
    LirCpu::builtin(
        LirCpuKind::Arm64,
        "arm64",
        64,
        LirCpuEndian::Little,
        registers,
        aliases,
        Some(LirCpuProgramCounter::new("pc", 64)),
        vec![
            LirMemory::stack("stack"),
            LirMemory::addressed("default", 64, LirCpuEndian::Little),
        ],
    )
}
