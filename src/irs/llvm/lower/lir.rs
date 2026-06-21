use crate::Configuration;
use crate::irs::lir::{LirBlock, LirCpu, LirCpuKind, LirFunction, LirModule};
use crate::irs::llvm::LlvmModule;
use std::io::Error;

pub trait LlvmFromLir {
    fn from_lir(
        &self,
        cpu: LirCpu,
        config: Configuration,
        triple: Option<String>,
    ) -> Result<LlvmModule, Error>;
}

impl LlvmFromLir for LirModule {
    fn from_lir(
        &self,
        cpu: LirCpu,
        config: Configuration,
        triple: Option<String>,
    ) -> Result<LlvmModule, Error> {
        validate_triple_for_cpu(&cpu, triple.as_deref())?;
        let mut lifter = LlvmModule::with_config(self.name.clone(), cpu.clone(), config, triple)?;
        for (index, function) in self.functions.iter().enumerate() {
            let function_name = function
                .name
                .clone()
                .or_else(|| self.name.clone())
                .unwrap_or_else(|| format!("function_{index}"));
            let function_module = LirModule {
                name: Some(function_name.clone()),
                functions: vec![LirFunction {
                    name: Some(function_name.clone()),
                    blocks: function.blocks.clone(),
                }],
                data: self.data.clone(),
            };
            lifter.populate_function_lir_named(&function_module, &function_name)?;
        }
        Ok(lifter)
    }
}

impl LlvmFromLir for LirFunction {
    fn from_lir(
        &self,
        cpu: LirCpu,
        config: Configuration,
        triple: Option<String>,
    ) -> Result<LlvmModule, Error> {
        let module = LirModule {
            name: self.name.clone(),
            functions: vec![self.clone()],
            data: Vec::new(),
        };
        module.from_lir(cpu, config, triple)
    }
}

impl LlvmFromLir for LirBlock {
    fn from_lir(
        &self,
        cpu: LirCpu,
        config: Configuration,
        triple: Option<String>,
    ) -> Result<LlvmModule, Error> {
        let function_name = self
            .name
            .clone()
            .unwrap_or_else(|| "function_0".to_string());
        let module = LirModule {
            name: Some(function_name.clone()),
            functions: vec![LirFunction {
                name: Some(function_name),
                blocks: vec![self.clone()],
            }],
            data: Vec::new(),
        };
        module.from_lir(cpu, config, triple)
    }
}

pub fn from_lir<T: LlvmFromLir>(
    lir: &T,
    cpu: LirCpu,
    config: Configuration,
    triple: Option<String>,
) -> Result<LlvmModule, Error> {
    lir.from_lir(cpu, config, triple)
}

fn validate_triple_for_cpu(cpu: &LirCpu, triple: Option<&str>) -> Result<(), Error> {
    let Some(triple) = triple else {
        return Ok(());
    };
    let target = triple
        .split_once('-')
        .map(|(target, _)| target)
        .unwrap_or(triple)
        .to_ascii_lowercase();
    let allowed = match cpu.kind() {
        Some(LirCpuKind::I386) => &["i386", "i486", "i586", "i686", "x86"][..],
        Some(LirCpuKind::Amd64) => &["x86_64", "amd64"][..],
        Some(LirCpuKind::Arm64) => &["aarch64", "arm64"][..],
        Some(LirCpuKind::Cil) => &["cil", "clr", "dotnet"][..],
        None => {
            return Err(Error::other("LLVM lowering requires a built-in LIR CPU"));
        }
    };
    if allowed.contains(&target.as_str()) {
        Ok(())
    } else {
        Err(Error::other(format!(
            "LLVM triple {triple:?} does not match LIR CPU {}; expected target prefix one of {}",
            cpu.kind()
                .map(|kind| format!("{kind:?}"))
                .unwrap_or_else(|| "custom".to_string()),
            allowed.join(", ")
        )))
    }
}
