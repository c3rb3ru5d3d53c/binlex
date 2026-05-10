use super::{
    SemanticCpu, SemanticCpuEndian, SemanticCpuKind, SemanticCpuProgramCounter,
    SemanticCpuRegister, SemanticMemory,
};
use crate::symbolic::Error;

pub fn build() -> Result<SemanticCpu, Error> {
    SemanticCpu::builtin(
        SemanticCpuKind::Cil,
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
