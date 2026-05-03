use super::error::{LifterCapability, LifterError};
use crate::controlflow::{Block, Function, Instruction};
use crate::semantics::InstructionSemantics;
use crate::{Architecture, Configuration};
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LifterBackend {
    #[default]
    Default,
    Llvm,
    Vex,
}

impl Display for LifterBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Default => "default",
            Self::Llvm => "llvm",
            Self::Vex => "vex",
        };
        write!(f, "{name}")
    }
}

enum ResolvedLifterBackend {
    Llvm(super::llvm::Lifter),
    #[cfg(not(target_os = "windows"))]
    Vex(super::vex::Lifter),
}

pub struct Lifter {
    architecture: Architecture,
    config: Configuration,
    backend: LifterBackend,
    inner: ResolvedLifterBackend,
}

pub enum Optimizers {
    Llvm(super::llvm::Optimizers),
}

impl Lifter {
    pub fn new(
        architecture: Architecture,
        config: Configuration,
        backend: LifterBackend,
    ) -> Result<Self, LifterError> {
        let resolved_backend = match backend {
            LifterBackend::Default | LifterBackend::Llvm => LifterBackend::Llvm,
            LifterBackend::Vex => LifterBackend::Vex,
        };

        let inner = match resolved_backend {
            LifterBackend::Llvm => {
                ResolvedLifterBackend::Llvm(super::llvm::Lifter::new(architecture, config.clone()))
            }
            LifterBackend::Vex => {
                #[cfg(not(target_os = "windows"))]
                {
                    ResolvedLifterBackend::Vex(super::vex::Lifter::new(config.clone()))
                }
                #[cfg(target_os = "windows")]
                {
                    return Err(LifterError::UnsupportedBackend {
                        backend: LifterBackend::Vex,
                        architecture,
                    });
                }
            }
            LifterBackend::Default => unreachable!(),
        };

        Ok(Self {
            architecture,
            config,
            backend: resolved_backend,
            inner,
        })
    }

    pub fn backend(&self) -> LifterBackend {
        self.backend
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn config(&self) -> &Configuration {
        &self.config
    }

    pub fn lift_instruction(&mut self, instruction: &Instruction) -> Result<(), LifterError> {
        match &mut self.inner {
            ResolvedLifterBackend::Llvm(lifter) => lifter.lift_instruction(instruction)?,
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(lifter) => lifter.lift_instruction(instruction)?,
        }
        Ok(())
    }

    pub fn lift_block(&mut self, block: &Block<'_>) -> Result<(), LifterError> {
        match &mut self.inner {
            ResolvedLifterBackend::Llvm(lifter) => lifter.lift_block(block)?,
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(lifter) => lifter.lift_block(block)?,
        }
        Ok(())
    }

    pub fn lift_function(&mut self, function: &Function<'_>) -> Result<(), LifterError> {
        match &mut self.inner {
            ResolvedLifterBackend::Llvm(lifter) => lifter.lift_function(function)?,
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(lifter) => lifter.lift_function(function)?,
        }
        Ok(())
    }

    pub fn lift_semantics(
        &mut self,
        semantics: &[InstructionSemantics],
    ) -> Result<(), LifterError> {
        match &mut self.inner {
            ResolvedLifterBackend::Llvm(lifter) => lifter.lift_semantics(semantics)?,
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => {
                return Err(self.unsupported(LifterCapability::LiftSemantics));
            }
        }
        Ok(())
    }

    pub fn text(&self) -> String {
        match &self.inner {
            ResolvedLifterBackend::Llvm(lifter) => lifter.text(),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(lifter) => lifter.text(),
        }
    }

    pub fn print(&self) {
        match &self.inner {
            ResolvedLifterBackend::Llvm(lifter) => lifter.print(),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(lifter) => lifter.print(),
        }
    }

    pub fn bitcode(&self) -> Result<Vec<u8>, LifterError> {
        match &self.inner {
            ResolvedLifterBackend::Llvm(lifter) => Ok(lifter.bitcode()),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(self.unsupported(LifterCapability::Bitcode)),
        }
    }

    pub fn embedding(&self) -> Result<Vec<f32>, LifterError> {
        match &self.inner {
            ResolvedLifterBackend::Llvm(lifter) => Ok(super::embeddings::embed_llvm_lifter(
                lifter,
                &self.config,
            )?),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(self.unsupported(LifterCapability::Embedding)),
        }
    }

    pub fn object(&self) -> Result<Vec<u8>, LifterError> {
        match &self.inner {
            ResolvedLifterBackend::Llvm(lifter) => Ok(lifter.object()?),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(self.unsupported(LifterCapability::Object)),
        }
    }

    pub fn verify(&self) -> Result<(), LifterError> {
        match &self.inner {
            ResolvedLifterBackend::Llvm(lifter) => {
                lifter.verify()?;
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(self.unsupported(LifterCapability::Verify)),
        }
    }

    pub fn optimizers(&self) -> Result<Optimizers, LifterError> {
        match &self.inner {
            ResolvedLifterBackend::Llvm(lifter) => Ok(Optimizers::Llvm(lifter.optimizers()?)),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(self.unsupported(LifterCapability::Optimizers)),
        }
    }

    pub fn mem2reg(&self) -> Result<Self, LifterError> {
        self.run_pass(LifterCapability::Mem2Reg)
    }

    pub fn instcombine(&self) -> Result<Self, LifterError> {
        self.run_pass(LifterCapability::InstCombine)
    }

    pub fn cfg(&self) -> Result<Self, LifterError> {
        self.run_pass(LifterCapability::Cfg)
    }

    pub fn gvn(&self) -> Result<Self, LifterError> {
        self.run_pass(LifterCapability::Gvn)
    }

    pub fn sroa(&self) -> Result<Self, LifterError> {
        self.run_pass(LifterCapability::Sroa)
    }

    pub fn dce(&self) -> Result<Self, LifterError> {
        self.run_pass(LifterCapability::Dce)
    }

    fn run_pass(&self, capability: LifterCapability) -> Result<Self, LifterError> {
        match &self.inner {
            ResolvedLifterBackend::Llvm(lifter) => {
                let inner = match capability {
                    LifterCapability::Mem2Reg => lifter.mem2reg()?,
                    LifterCapability::InstCombine => lifter.instcombine()?,
                    LifterCapability::Cfg => lifter.cfg()?,
                    LifterCapability::Gvn => lifter.gvn()?,
                    LifterCapability::Sroa => lifter.sroa()?,
                    LifterCapability::Dce => lifter.dce()?,
                    _ => unreachable!(),
                };
                Ok(Self {
                    architecture: self.architecture,
                    config: self.config.clone(),
                    backend: self.backend,
                    inner: ResolvedLifterBackend::Llvm(inner),
                })
            }
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(self.unsupported(capability)),
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn unsupported(&self, capability: LifterCapability) -> LifterError {
        LifterError::UnsupportedCapability {
            backend: self.backend,
            capability,
        }
    }
}

impl Optimizers {
    pub fn mem2reg(self) -> Result<Self, LifterError> {
        match self {
            Self::Llvm(optimizers) => Ok(Self::Llvm(optimizers.mem2reg()?)),
        }
    }

    pub fn instcombine(self) -> Result<Self, LifterError> {
        match self {
            Self::Llvm(optimizers) => Ok(Self::Llvm(optimizers.instcombine()?)),
        }
    }

    pub fn cfg(self) -> Result<Self, LifterError> {
        match self {
            Self::Llvm(optimizers) => Ok(Self::Llvm(optimizers.cfg()?)),
        }
    }

    pub fn gvn(self) -> Result<Self, LifterError> {
        match self {
            Self::Llvm(optimizers) => Ok(Self::Llvm(optimizers.gvn()?)),
        }
    }

    pub fn sroa(self) -> Result<Self, LifterError> {
        match self {
            Self::Llvm(optimizers) => Ok(Self::Llvm(optimizers.sroa()?)),
        }
    }

    pub fn dce(self) -> Result<Self, LifterError> {
        match self {
            Self::Llvm(optimizers) => Ok(Self::Llvm(optimizers.dce()?)),
        }
    }

    pub fn text(&self) -> String {
        match self {
            Self::Llvm(optimizers) => optimizers.text(),
        }
    }

    pub fn bitcode(&self) -> Vec<u8> {
        match self {
            Self::Llvm(optimizers) => optimizers.bitcode(),
        }
    }

    pub fn verify(&self) -> Result<(), LifterError> {
        match self {
            Self::Llvm(optimizers) => {
                optimizers.verify()?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Lifter, LifterBackend};
    use crate::{Architecture, Configuration};

    #[test]
    fn default_backend_resolves_to_llvm() {
        let lifter = Lifter::new(
            Architecture::AMD64,
            Configuration::default(),
            LifterBackend::Default,
        )
        .expect("lifter");
        assert_eq!(lifter.backend(), LifterBackend::Llvm);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn vex_reports_unsupported_llvm_capabilities() {
        let lifter = Lifter::new(
            Architecture::AMD64,
            Configuration::default(),
            LifterBackend::Vex,
        )
        .expect("lifter");
        assert!(lifter.bitcode().is_err());
        assert!(lifter.optimizers().is_err());
    }
}
