use crate::Configuration;
use crate::irs::lir::{LirBlock, LirFunction, LirModule};
use crate::irs::vex::VexModule;
use std::io::Error;

pub trait VexFromLir {
    fn from_lir(&self, config: Configuration) -> Result<VexModule, Error>;
}

impl VexFromLir for LirBlock {
    fn from_lir(&self, config: Configuration) -> Result<VexModule, Error> {
        let function = LirFunction {
            name: self.name.clone(),
            abi: None,
            blocks: vec![self.clone()],
        };
        function.from_lir(config)
    }
}

impl VexFromLir for LirFunction {
    fn from_lir(&self, config: Configuration) -> Result<VexModule, Error> {
        let module = LirModule {
            name: self.name.clone(),
            functions: vec![self.clone()],
            data: Vec::new(),
        };
        module.from_lir(config)
    }
}

impl VexFromLir for LirModule {
    fn from_lir(&self, config: Configuration) -> Result<VexModule, Error> {
        let mut module = VexModule::new(self.name.clone());
        module.from_lir(self, config)?;
        Ok(module)
    }
}

pub fn from_lir<T: VexFromLir>(lir: &T, config: Configuration) -> Result<VexModule, Error> {
    lir.from_lir(config)
}
