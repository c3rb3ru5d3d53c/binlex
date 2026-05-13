use super::error::{LifterCapability, LifterError};
use crate::controlflow::{Block, Function, Graph, Instruction, InstructionRecord};
use crate::semantics::{
    Semantic, SemanticAbi, SemanticCpu, SemanticExpression, SemanticTerminator, Semantics,
};
use crate::{Architecture, Configuration};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::io::Error;
use std::sync::{Arc, Mutex};

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

#[derive(Clone)]
enum ModuleItemDef {
    BlockSemantics {
        semantics: Semantics,
        abi: Option<SemanticAbi>,
    },
    FunctionSemantics {
        semantics: Semantics,
        abi: Option<SemanticAbi>,
        name: Option<String>,
    },
    CreatedFunction {
        function: CreatedFunctionDef,
    },
}

#[derive(Clone)]
enum ModuleOverrideDef {
    Ir(String),
    Bitcode(Vec<u8>),
}

#[derive(Clone)]
struct CreatedFunctionDef {
    name: String,
    abi: Option<SemanticAbi>,
    body_semantics: Option<Semantics>,
    blocks: Vec<CreatedBlockDef>,
    raw_ir: Option<String>,
    raw_bitcode: Option<Vec<u8>>,
}

#[derive(Clone)]
enum CreatedBlockDef {
    Cfg {
        name: Option<String>,
        address: u64,
        records: Vec<InstructionRecord>,
    },
    Semantics {
        name: Option<String>,
        semantics: Semantics,
    },
}

struct BuildState {
    cpu: SemanticCpu,
    architecture: Architecture,
    triple: Option<String>,
    config: Configuration,
    backend: LifterBackend,
    inner: ResolvedLifterBackend,
    module_override: Option<ModuleOverrideDef>,
    items: Vec<ModuleItemDef>,
    dirty: bool,
}

#[derive(Clone)]
pub struct Lifter {
    state: Arc<Mutex<BuildState>>,
}

#[derive(Clone)]
pub struct LiftedFunction {
    state: Arc<Mutex<BuildState>>,
    index: usize,
}

#[derive(Clone)]
pub struct LiftedBlock {
    state: Arc<Mutex<BuildState>>,
    function_index: usize,
    block_index: usize,
}

pub struct JittedFunction {
    inner: super::llvm::JittedFunction,
}

impl BuildState {
    fn new(
        cpu: SemanticCpu,
        config: Configuration,
        backend: LifterBackend,
        triple: Option<String>,
    ) -> Result<Self, LifterError> {
        let architecture = architecture_from_cpu(&cpu)?;
        let resolved_backend = match backend {
            LifterBackend::Default | LifterBackend::Llvm => LifterBackend::Llvm,
            LifterBackend::Vex => LifterBackend::Vex,
        };
        let inner = Self::new_inner(
            &cpu,
            &config,
            architecture,
            resolved_backend,
            triple.as_deref(),
        )?;
        Ok(Self {
            cpu,
            architecture,
            triple,
            config,
            backend: resolved_backend,
            inner,
            module_override: None,
            items: Vec::new(),
            dirty: false,
        })
    }

    fn new_inner(
        cpu: &SemanticCpu,
        config: &Configuration,
        _architecture: Architecture,
        backend: LifterBackend,
        triple: Option<&str>,
    ) -> Result<ResolvedLifterBackend, LifterError> {
        match backend {
            LifterBackend::Llvm => Ok(ResolvedLifterBackend::Llvm(super::llvm::Lifter::new(
                cpu.clone(),
                config.clone(),
                triple.map(str::to_string),
            )?)),
            LifterBackend::Vex => {
                #[cfg(not(target_os = "windows"))]
                {
                    Ok(ResolvedLifterBackend::Vex(super::vex::Lifter::new(
                        config.clone(),
                    )))
                }
                #[cfg(target_os = "windows")]
                {
                    Err(LifterError::UnsupportedBackend {
                        backend: LifterBackend::Vex,
                        architecture: _architecture,
                    })
                }
            }
            LifterBackend::Default => unreachable!(),
        }
    }

    fn rebuild(&mut self) -> Result<(), LifterError> {
        let mut inner = Self::new_inner(
            &self.cpu,
            &self.config,
            self.architecture,
            self.backend,
            self.triple.as_deref(),
        )?;
        if let Some(override_def) = self.module_override.clone() {
            match (&mut inner, override_def) {
                (ResolvedLifterBackend::Llvm(lifter), ModuleOverrideDef::Ir(ir)) => {
                    lifter.set_ir(&ir)?
                }
                (ResolvedLifterBackend::Llvm(lifter), ModuleOverrideDef::Bitcode(bitcode)) => {
                    lifter.set_bitcode(&bitcode)?
                }
                #[cfg(not(target_os = "windows"))]
                (ResolvedLifterBackend::Vex(_), _) => {
                    return Err(self.unsupported(LifterCapability::SetIr));
                }
            }
        }
        for item in self.items.clone() {
            self.apply_item(&mut inner, item)?;
        }
        self.inner = inner;
        self.dirty = false;
        Ok(())
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn ensure_built(&mut self) -> Result<(), LifterError> {
        if self.dirty {
            self.rebuild()?;
        }
        Ok(())
    }

    fn apply_item(
        &self,
        inner: &mut ResolvedLifterBackend,
        item: ModuleItemDef,
    ) -> Result<(), LifterError> {
        Self::apply_item_static(&self.config, self.architecture, self.backend, inner, item)
    }

    fn apply_item_static(
        config: &Configuration,
        architecture: Architecture,
        backend: LifterBackend,
        inner: &mut ResolvedLifterBackend,
        item: ModuleItemDef,
    ) -> Result<(), LifterError> {
        match item {
            ModuleItemDef::BlockSemantics { semantics, abi } => match inner {
                ResolvedLifterBackend::Llvm(lifter) => {
                    lifter.lift_block_semantics(&semantics, abi.as_ref())?
                }
                #[cfg(not(target_os = "windows"))]
                ResolvedLifterBackend::Vex(_) => {
                    return Err(LifterError::UnsupportedCapability {
                        backend,
                        capability: LifterCapability::LiftBlockSemantics,
                    });
                }
            },
            ModuleItemDef::FunctionSemantics {
                semantics,
                abi,
                name,
            } => match inner {
                ResolvedLifterBackend::Llvm(lifter) => {
                    if let Some(name) = name {
                        lifter.lift_function_semantics_named(&semantics, abi.as_ref(), &name)?;
                    } else {
                        lifter.lift_function_semantics(&semantics, abi.as_ref())?;
                    }
                }
                #[cfg(not(target_os = "windows"))]
                ResolvedLifterBackend::Vex(_) => {
                    return Err(LifterError::UnsupportedCapability {
                        backend,
                        capability: LifterCapability::LiftFunctionSemantics,
                    });
                }
            },
            ModuleItemDef::CreatedFunction { function } => match inner {
                ResolvedLifterBackend::Llvm(lifter) => {
                    compile_created_function(lifter, config, architecture, &function)?
                }
                #[cfg(not(target_os = "windows"))]
                ResolvedLifterBackend::Vex(_) => {
                    return Err(LifterError::UnsupportedCapability {
                        backend,
                        capability: LifterCapability::CreateFunction,
                    });
                }
            },
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn unsupported(&self, capability: LifterCapability) -> LifterError {
        LifterError::UnsupportedCapability {
            backend: self.backend,
            capability,
        }
    }
}

impl Lifter {
    pub fn from_architecture(
        architecture: Architecture,
        config: Configuration,
        backend: LifterBackend,
    ) -> Result<Self, LifterError> {
        let cpu = SemanticCpu::from_architecture(architecture)
            .map_err(|error| LifterError::Io(Error::other(error.to_string())))?;
        Self::new(cpu, config, backend, None)
    }

    pub fn new(
        cpu: SemanticCpu,
        config: Configuration,
        backend: LifterBackend,
        triple: Option<String>,
    ) -> Result<Self, LifterError> {
        let state = BuildState::new(cpu, config, backend, triple)?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn backend(&self) -> LifterBackend {
        self.state.lock().unwrap().backend
    }

    pub fn cpu(&self) -> SemanticCpu {
        self.state.lock().unwrap().cpu.clone()
    }

    pub fn architecture(&self) -> Architecture {
        self.state.lock().unwrap().architecture
    }

    pub fn config(&self) -> Configuration {
        self.state.lock().unwrap().config.clone()
    }

    pub fn lift_instruction(&self, instruction: &Instruction) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::CreateFunction));
        }
        let name = format!("instruction_{:x}", instruction.address);
        state.items.push(ModuleItemDef::CreatedFunction {
            function: CreatedFunctionDef {
                name,
                abi: None,
                body_semantics: None,
                blocks: vec![CreatedBlockDef::Cfg {
                    name: None,
                    address: instruction.address,
                    records: vec![instruction.clone().into_record()],
                }],
                raw_ir: None,
                raw_bitcode: None,
            },
        });
        state.mark_dirty();
        Ok(())
    }

    pub fn lift_block(
        &self,
        block: &Block<'_>,
        abi: Option<&SemanticAbi>,
    ) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::CreateFunction));
        }
        let name = format!("block_{:x}", block.address());
        state.items.push(ModuleItemDef::CreatedFunction {
            function: CreatedFunctionDef {
                name,
                abi: abi.cloned(),
                body_semantics: None,
                blocks: vec![CreatedBlockDef::Cfg {
                    name: None,
                    address: block.address(),
                    records: instruction_records_for_block(block.cfg, block.address())?,
                }],
                raw_ir: None,
                raw_bitcode: None,
            },
        });
        state.mark_dirty();
        Ok(())
    }

    pub fn lift_function(
        &self,
        function: &Function<'_>,
        abi: Option<&SemanticAbi>,
    ) -> Result<(), LifterError> {
        self.lift_function_named(function, abi, None)
    }

    pub fn lift_function_named(
        &self,
        function: &Function<'_>,
        abi: Option<&SemanticAbi>,
        name: Option<&str>,
    ) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::CreateFunction));
        }
        let function_name = name
            .map(str::to_string)
            .unwrap_or_else(|| format!("function_{:x}", function.address()));
        let mut blocks = Vec::with_capacity(function.blocks.len());
        for block in function.blocks.values() {
            blocks.push(CreatedBlockDef::Cfg {
                name: None,
                address: block.address(),
                records: instruction_records_for_block(function.cfg, block.address())?,
            });
        }
        state.items.push(ModuleItemDef::CreatedFunction {
            function: CreatedFunctionDef {
                name: function_name,
                abi: abi.cloned(),
                body_semantics: None,
                blocks,
                raw_ir: None,
                raw_bitcode: None,
            },
        });
        state.mark_dirty();
        Ok(())
    }

    pub fn lift_block_semantics(
        &self,
        semantics: &Semantics,
        abi: Option<&SemanticAbi>,
    ) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_built()?;
        BuildState::apply_item_static(
            &state.config.clone(),
            state.architecture,
            state.backend,
            &mut state.inner,
            ModuleItemDef::BlockSemantics {
                semantics: semantics.clone(),
                abi: abi.cloned(),
            },
        )?;
        state.items.push(ModuleItemDef::BlockSemantics {
            semantics: semantics.clone(),
            abi: abi.cloned(),
        });
        state.dirty = false;
        Ok(())
    }

    pub fn lift_function_semantics(
        &self,
        semantics: &Semantics,
        abi: Option<&SemanticAbi>,
    ) -> Result<(), LifterError> {
        self.lift_function_semantics_named(semantics, abi, None)
    }

    pub fn lift_function_semantics_named(
        &self,
        semantics: &Semantics,
        abi: Option<&SemanticAbi>,
        name: Option<&str>,
    ) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_built()?;
        let item = ModuleItemDef::FunctionSemantics {
            semantics: semantics.clone(),
            abi: abi.cloned(),
            name: name.map(str::to_string),
        };
        BuildState::apply_item_static(
            &state.config.clone(),
            state.architecture,
            state.backend,
            &mut state.inner,
            item.clone(),
        )?;
        state.items.push(item);
        state.dirty = false;
        Ok(())
    }

    pub fn create_function(
        &self,
        name: impl Into<String>,
        abi: Option<&SemanticAbi>,
    ) -> Result<LiftedFunction, LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::CreateFunction));
        }
        let index = state.items.len();
        state.items.push(ModuleItemDef::CreatedFunction {
            function: CreatedFunctionDef {
                name: name.into(),
                abi: abi.cloned(),
                body_semantics: None,
                blocks: Vec::new(),
                raw_ir: None,
                raw_bitcode: None,
            },
        });
        state.mark_dirty();
        Ok(LiftedFunction {
            state: self.state.clone(),
            index,
        })
    }

    pub fn functions(&self) -> Result<Vec<LiftedFunction>, LifterError> {
        let state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::Functions));
        }
        Ok(state
            .items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| match item {
                ModuleItemDef::CreatedFunction { .. } => Some(LiftedFunction {
                    state: self.state.clone(),
                    index,
                }),
                _ => None,
            })
            .collect())
    }

    pub fn clear(&self) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        state.module_override = None;
        state.items.clear();
        state.rebuild()
    }

    pub fn ir(&self) -> String {
        let mut state = self.state.lock().unwrap();
        let _ = state.ensure_built();
        match &state.inner {
            ResolvedLifterBackend::Llvm(lifter) => lifter.ir(),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(lifter) => lifter.ir(),
        }
    }

    pub fn print(&self) {
        println!("{}", self.ir());
    }

    pub fn set_ir(&self, ir: &str) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::SetIr));
        }
        state.module_override = Some(ModuleOverrideDef::Ir(ir.to_string()));
        state.items.clear();
        state.rebuild()
    }

    pub fn set_bitcode(&self, bitcode: &[u8]) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::SetBitcode));
        }
        state.module_override = Some(ModuleOverrideDef::Bitcode(bitcode.to_vec()));
        state.items.clear();
        state.rebuild()
    }

    pub fn bitcode(&self) -> Result<Vec<u8>, LifterError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_built()?;
        match &state.inner {
            ResolvedLifterBackend::Llvm(lifter) => Ok(lifter.bitcode()),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(state.unsupported(LifterCapability::Bitcode)),
        }
    }

    pub fn object(&self) -> Result<Vec<u8>, LifterError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_built()?;
        match &state.inner {
            ResolvedLifterBackend::Llvm(lifter) => Ok(lifter.object()?),
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(state.unsupported(LifterCapability::Object)),
        }
    }

    pub fn verify(&self) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_built()?;
        match &state.inner {
            ResolvedLifterBackend::Llvm(lifter) => {
                lifter.verify()?;
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(state.unsupported(LifterCapability::Verify)),
        }
    }

    pub fn optimize_mem2reg(&self) -> Result<(), LifterError> {
        self.optimize_module_pass(LifterCapability::Mem2Reg)
    }

    pub fn optimize_instcombine(&self) -> Result<(), LifterError> {
        self.optimize_module_pass(LifterCapability::InstCombine)
    }

    pub fn optimize_cfg(&self) -> Result<(), LifterError> {
        self.optimize_module_pass(LifterCapability::Cfg)
    }

    pub fn optimize_gvn(&self) -> Result<(), LifterError> {
        self.optimize_module_pass(LifterCapability::Gvn)
    }

    pub fn optimize_sroa(&self) -> Result<(), LifterError> {
        self.optimize_module_pass(LifterCapability::Sroa)
    }

    pub fn optimize_dce(&self) -> Result<(), LifterError> {
        self.optimize_module_pass(LifterCapability::Dce)
    }

    fn optimize_module_pass(&self, capability: LifterCapability) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_built()?;
        match &state.inner {
            ResolvedLifterBackend::Llvm(lifter) => {
                let optimized = match capability {
                    LifterCapability::Mem2Reg => lifter.mem2reg()?,
                    LifterCapability::InstCombine => lifter.instcombine()?,
                    LifterCapability::Cfg => lifter.cfg()?,
                    LifterCapability::Gvn => lifter.gvn()?,
                    LifterCapability::Sroa => lifter.sroa()?,
                    LifterCapability::Dce => lifter.dce()?,
                    _ => unreachable!(),
                };
                state.inner = ResolvedLifterBackend::Llvm(optimized);
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(state.unsupported(capability)),
        }
    }
}

impl LiftedFunction {
    pub fn name(&self) -> String {
        let state = self.state.lock().unwrap();
        match &state.items[self.index] {
            ModuleItemDef::CreatedFunction { function } => function.name.clone(),
            _ => String::new(),
        }
    }

    pub fn set_name(&self, name: impl Into<String>) -> Result<(), LifterError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(LifterError::Io(Error::other(
                "lifted function name cannot be empty",
            )));
        }
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return Err(LifterError::Io(Error::other("lifted function is invalid")));
        };
        function.name = name;
        state.mark_dirty();
        Ok(())
    }

    pub fn blocks(&self) -> Vec<LiftedBlock> {
        let state = self.state.lock().unwrap();
        let count = match &state.items[self.index] {
            ModuleItemDef::CreatedFunction { function } => function.blocks.len(),
            _ => 0,
        };
        (0..count)
            .map(|block_index| LiftedBlock {
                state: self.state.clone(),
                function_index: self.index,
                block_index,
            })
            .collect()
    }

    pub fn lift_block(&self, block: &Block<'_>, name: Option<&str>) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::CreateFunction));
        }
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return Err(LifterError::Io(Error::other("lifted function is invalid")));
        };
        if function.body_semantics.is_some() {
            return Err(LifterError::Io(Error::other(
                "function already has semantic body",
            )));
        }
        if function.raw_ir.is_some() || function.raw_bitcode.is_some() {
            return Err(LifterError::Io(Error::other(
                "function already has raw llvm body",
            )));
        }
        function.blocks.push(CreatedBlockDef::Cfg {
            name: name.map(str::to_string),
            address: block.address(),
            records: instruction_records_for_block(block.cfg, block.address())?,
        });
        state.mark_dirty();
        Ok(())
    }

    pub fn lift_block_semantics(
        &self,
        semantics: &Semantics,
        name: Option<&str>,
    ) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::CreateFunction));
        }
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return Err(LifterError::Io(Error::other("lifted function is invalid")));
        };
        if function.body_semantics.is_some() {
            return Err(LifterError::Io(Error::other(
                "function already has semantic body",
            )));
        }
        if function.raw_ir.is_some() || function.raw_bitcode.is_some() {
            return Err(LifterError::Io(Error::other(
                "function already has raw llvm body",
            )));
        }
        function.blocks.push(CreatedBlockDef::Semantics {
            name: name.map(str::to_string),
            semantics: semantics.clone(),
        });
        state.mark_dirty();
        Ok(())
    }

    pub fn lift_function_semantics(&self, semantics: &Semantics) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        #[cfg(not(target_os = "windows"))]
        if state.backend != LifterBackend::Llvm {
            return Err(state.unsupported(LifterCapability::CreateFunction));
        }
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return Err(LifterError::Io(Error::other("lifted function is invalid")));
        };
        if !function.blocks.is_empty() {
            return Err(LifterError::Io(Error::other("function already has blocks")));
        }
        if function.raw_ir.is_some() || function.raw_bitcode.is_some() {
            return Err(LifterError::Io(Error::other(
                "function already has raw llvm body",
            )));
        }
        function.body_semantics = Some(semantics.clone());
        state.mark_dirty();
        Ok(())
    }

    pub fn optimize_mem2reg(&self) -> Result<(), LifterError> {
        self.optimize_function_pass(LifterCapability::Mem2Reg)
    }

    pub fn optimize_instcombine(&self) -> Result<(), LifterError> {
        self.optimize_function_pass(LifterCapability::InstCombine)
    }

    pub fn optimize_cfg(&self) -> Result<(), LifterError> {
        self.optimize_function_pass(LifterCapability::Cfg)
    }

    pub fn optimize_gvn(&self) -> Result<(), LifterError> {
        self.optimize_function_pass(LifterCapability::Gvn)
    }

    pub fn optimize_sroa(&self) -> Result<(), LifterError> {
        self.optimize_function_pass(LifterCapability::Sroa)
    }

    pub fn optimize_dce(&self) -> Result<(), LifterError> {
        self.optimize_function_pass(LifterCapability::Dce)
    }

    fn optimize_function_pass(&self, capability: LifterCapability) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        state.ensure_built()?;
        let name = match &state.items[self.index] {
            ModuleItemDef::CreatedFunction { function } => function.name.clone(),
            _ => return Err(LifterError::Io(Error::other("lifted function is invalid"))),
        };
        match &state.inner {
            ResolvedLifterBackend::Llvm(lifter) => {
                let optimized = match capability {
                    LifterCapability::Mem2Reg => lifter.mem2reg_function(&name)?,
                    LifterCapability::InstCombine => lifter.instcombine_function(&name)?,
                    LifterCapability::Cfg => lifter.cfg_function(&name)?,
                    LifterCapability::Gvn => lifter.gvn_function(&name)?,
                    LifterCapability::Sroa => lifter.sroa_function(&name)?,
                    LifterCapability::Dce => lifter.dce_function(&name)?,
                    _ => unreachable!(),
                };
                state.inner = ResolvedLifterBackend::Llvm(optimized);
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            ResolvedLifterBackend::Vex(_) => Err(state.unsupported(capability)),
        }
    }

    pub fn ir(&self) -> Result<String, LifterError> {
        let state = self.state.lock().unwrap();
        let name = match state.items.get(self.index) {
            Some(ModuleItemDef::CreatedFunction { function }) => function.name.clone(),
            _ => return Err(LifterError::Io(Error::other("lifted function is invalid"))),
        };
        if !state.dirty {
            match &state.inner {
                ResolvedLifterBackend::Llvm(lifter) => {
                    return lifter
                        .duplicate_function_view(&name)
                        .map(|lifter| lifter.ir())
                        .map_err(LifterError::Io);
                }
                #[cfg(not(target_os = "windows"))]
                ResolvedLifterBackend::Vex(_) => {}
            }
        }
        drop(state);
        let lifter = self.preview_lifter()?;
        Ok(lifter.ir())
    }

    pub fn print(&self) -> Result<(), LifterError> {
        let text = self.ir()?;
        println!("{text}");
        Ok(())
    }

    pub fn bitcode(&self) -> Result<Vec<u8>, LifterError> {
        let state = self.state.lock().unwrap();
        let name = match state.items.get(self.index) {
            Some(ModuleItemDef::CreatedFunction { function }) => function.name.clone(),
            _ => return Err(LifterError::Io(Error::other("lifted function is invalid"))),
        };
        if !state.dirty {
            match &state.inner {
                ResolvedLifterBackend::Llvm(lifter) => {
                    return lifter
                        .duplicate_function_view(&name)
                        .map(|lifter| lifter.bitcode())
                        .map_err(LifterError::Io);
                }
                #[cfg(not(target_os = "windows"))]
                ResolvedLifterBackend::Vex(_) => {}
            }
        }
        drop(state);
        let lifter = self.preview_lifter()?;
        lifter.bitcode()
    }

    pub fn object(&self) -> Result<Vec<u8>, LifterError> {
        let state = self.state.lock().unwrap();
        let name = match state.items.get(self.index) {
            Some(ModuleItemDef::CreatedFunction { function }) => function.name.clone(),
            _ => return Err(LifterError::Io(Error::other("lifted function is invalid"))),
        };
        if !state.dirty {
            match &state.inner {
                ResolvedLifterBackend::Llvm(lifter) => {
                    return lifter
                        .duplicate_function_view(&name)
                        .and_then(|lifter| lifter.object())
                        .map_err(LifterError::Io);
                }
                #[cfg(not(target_os = "windows"))]
                ResolvedLifterBackend::Vex(_) => {}
            }
        }
        drop(state);
        let lifter = self.preview_lifter()?;
        lifter.object()
    }

    pub fn jit(&self, links: &BTreeMap<String, usize>) -> Result<JittedFunction, LifterError> {
        let state = self.state.lock().unwrap();
        let name = match state.items.get(self.index) {
            Some(ModuleItemDef::CreatedFunction { function }) => function.name.clone(),
            _ => return Err(LifterError::Io(Error::other("lifted function is invalid"))),
        };
        let preserve_links = !links.is_empty();
        let lifter = if !state.dirty {
            match &state.inner {
                ResolvedLifterBackend::Llvm(lifter) => {
                    if preserve_links {
                        let mut duplicate = super::llvm::Lifter::new(
                            state.cpu.clone(),
                            state.config.clone(),
                            state.triple.clone(),
                        )?;
                        duplicate.set_bitcode(&lifter.bitcode())?;
                        duplicate
                    } else {
                        lifter.duplicate_function_view(&name)?
                    }
                }
                #[cfg(not(target_os = "windows"))]
                ResolvedLifterBackend::Vex(_) => {
                    return Err(state.unsupported(LifterCapability::Jit));
                }
            }
        } else {
            drop(state);
            let preview = self.preview_lifter()?;
            let mut preview_state = preview.state.lock().unwrap();
            preview_state.ensure_built()?;
            match &preview_state.inner {
                ResolvedLifterBackend::Llvm(lifter) => lifter.duplicate()?,
                #[cfg(not(target_os = "windows"))]
                ResolvedLifterBackend::Vex(_) => {
                    return Err(LifterError::UnsupportedCapability {
                        backend: LifterBackend::Vex,
                        capability: LifterCapability::Jit,
                    });
                }
            }
        };
        let inner = lifter.jit_function(&name, links)?;
        Ok(JittedFunction { inner })
    }

    fn preview_lifter(&self) -> Result<Lifter, LifterError> {
        let state = self.state.lock().unwrap();
        let item = state
            .items
            .get(self.index)
            .cloned()
            .ok_or_else(|| LifterError::Io(Error::other("lifted function is invalid")))?;
        let ModuleItemDef::CreatedFunction { function } = item else {
            return Err(LifterError::Io(Error::other("lifted function is invalid")));
        };
        preview_lifter_from_items(&state, vec![ModuleItemDef::CreatedFunction { function }])
    }

    pub fn set_ir(&self, ir: &str) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return Err(LifterError::Io(Error::other("lifted function is invalid")));
        };
        function.body_semantics = None;
        function.blocks.clear();
        function.raw_bitcode = None;
        function.raw_ir = Some(ir.to_string());
        state.mark_dirty();
        Ok(())
    }

    pub fn set_bitcode(&self, bitcode: &[u8]) -> Result<(), LifterError> {
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return Err(LifterError::Io(Error::other("lifted function is invalid")));
        };
        function.body_semantics = None;
        function.blocks.clear();
        function.raw_ir = None;
        function.raw_bitcode = Some(bitcode.to_vec());
        state.mark_dirty();
        Ok(())
    }
}

impl JittedFunction {
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    pub fn address(&self) -> usize {
        self.inner.address()
    }
}

impl LiftedBlock {
    pub fn name(&self) -> String {
        let state = self.state.lock().unwrap();
        let Some(ModuleItemDef::CreatedFunction { function }) =
            state.items.get(self.function_index)
        else {
            return String::new();
        };
        match &function.blocks[self.block_index] {
            CreatedBlockDef::Cfg { name, address, .. } => {
                name.clone().unwrap_or_else(|| format!("block_{address:x}"))
            }
            CreatedBlockDef::Semantics { name, .. } => name
                .clone()
                .unwrap_or_else(|| format!("block_{}", self.block_index)),
        }
    }

    pub fn ir(&self) -> Result<String, LifterError> {
        let lifter = self.preview_lifter()?;
        Ok(lifter.ir())
    }

    pub fn print(&self) -> Result<(), LifterError> {
        let text = self.ir()?;
        println!("{text}");
        Ok(())
    }

    fn preview_lifter(&self) -> Result<Lifter, LifterError> {
        let state = self.state.lock().unwrap();
        let item = state
            .items
            .get(self.function_index)
            .cloned()
            .ok_or_else(|| LifterError::Io(Error::other("lifted block is invalid")))?;
        let ModuleItemDef::CreatedFunction { function } = item else {
            return Err(LifterError::Io(Error::other("lifted block is invalid")));
        };
        let block = function
            .blocks
            .get(self.block_index)
            .cloned()
            .ok_or_else(|| LifterError::Io(Error::other("lifted block is invalid")))?;
        let name = block_preview_function_name(&function.name, &block, self.block_index);
        let preview = CreatedFunctionDef {
            name,
            abi: function.abi.clone(),
            body_semantics: None,
            blocks: vec![block],
            raw_ir: None,
            raw_bitcode: None,
        };
        preview_lifter_from_items(
            &state,
            vec![ModuleItemDef::CreatedFunction { function: preview }],
        )
    }
}

fn preview_lifter_from_items(
    state: &BuildState,
    items: Vec<ModuleItemDef>,
) -> Result<Lifter, LifterError> {
    let preview = Lifter::new(
        state.cpu.clone(),
        state.config.clone(),
        state.backend,
        state.triple.clone(),
    )?;
    {
        let mut preview_state = preview.state.lock().unwrap();
        preview_state.items = items;
        preview_state.mark_dirty();
        preview_state.ensure_built()?;
    }
    Ok(preview)
}

fn block_preview_function_name(
    function_name: &str,
    block: &CreatedBlockDef,
    block_index: usize,
) -> String {
    match block {
        CreatedBlockDef::Cfg { name, address, .. } => name
            .clone()
            .unwrap_or_else(|| format!("{function_name}_block_{address:x}")),
        CreatedBlockDef::Semantics { name, .. } => name
            .clone()
            .unwrap_or_else(|| format!("{function_name}_block_{block_index}")),
    }
}

fn instruction_records_for_block(
    graph: &Graph,
    address: u64,
) -> Result<Vec<InstructionRecord>, Error> {
    let block = Block::new(address, graph)?;
    Ok(block
        .instructions()
        .into_iter()
        .map(Instruction::into_record)
        .collect())
}

fn compile_created_function(
    inner: &mut super::llvm::Lifter,
    config: &Configuration,
    architecture: Architecture,
    function: &CreatedFunctionDef,
) -> Result<(), Error> {
    if let Some(ir) = &function.raw_ir {
        return inner.link_ir_module(ir, Some(&function.name));
    }
    if let Some(bitcode) = &function.raw_bitcode {
        return inner.link_bitcode_module(bitcode, Some(&function.name));
    }
    if let Some(semantics) = &function.body_semantics {
        return inner.lift_function_semantics_named(
            semantics,
            function.abi.as_ref(),
            &function.name,
        );
    }

    let mut graph = Graph::new(architecture, config.clone());
    let mut block_labels = BTreeMap::<u64, String>::new();
    let mut next_block_base = 0x1000u64;
    let mut entry_address = None;

    for (index, block) in function.blocks.iter().enumerate() {
        match block {
            CreatedBlockDef::Cfg {
                name,
                address: _,
                records,
            } => {
                let block_address = records
                    .first()
                    .map(|record| record.address)
                    .ok_or_else(|| Error::other("cfg block contains no instructions"))?;
                if entry_address.is_none() {
                    entry_address = Some(block_address);
                }
                for record in records.iter().cloned() {
                    graph.insert_instruction(record);
                }
                graph.set_block(block_address);
                if let Some(name) = name {
                    block_labels.insert(block_address, name.clone());
                }
            }
            CreatedBlockDef::Semantics { name, semantics } => {
                let block_address = next_block_base;
                if entry_address.is_none() {
                    entry_address = Some(block_address);
                }
                if let Some(name) = name {
                    block_labels.insert(block_address, name.clone());
                }
                let next_block_address = function
                    .blocks
                    .get(index + 1)
                    .map(|_| next_block_base + 0x1000);
                insert_semantics_block(
                    &mut graph,
                    architecture,
                    block_address,
                    &semantics.semantics,
                    next_block_address,
                    config,
                );
                graph.set_block(block_address);
                next_block_base += 0x1000;
            }
        }
    }

    let entry_address = entry_address.ok_or_else(|| Error::other("function contains no blocks"))?;
    graph.set_function(entry_address);
    let function_graph = Function::new(entry_address, &graph)?;
    inner.lift_function_named(
        &function_graph,
        function.abi.as_ref(),
        &function.name,
        Some(&block_labels),
    )
}

fn insert_semantics_block(
    graph: &mut Graph,
    architecture: Architecture,
    block_address: u64,
    semantics: &[Semantic],
    next_block_address: Option<u64>,
    config: &Configuration,
) {
    for (index, semantic) in semantics.iter().enumerate() {
        let address = block_address + index as u64;
        let mut record = Instruction::create(address, architecture, config.clone());
        record.bytes = vec![0x90];
        record.mnemonic = "semantic".to_string();
        record.disassembly = "semantic".to_string();
        record.pattern = "90".to_string();
        record.semantics = Some(semantic.clone());
        if index == 0 {
            record.is_block_start = true;
        }
        if index == semantics.len() - 1 {
            match &semantic.terminator {
                SemanticTerminator::Return { .. } => {
                    record.is_return = true;
                }
                SemanticTerminator::Jump { target } => {
                    record.is_jump = true;
                    if let Some(address) = semantic_expression_u64(target) {
                        record.to.insert(address);
                    } else if let Some(next) = next_block_address {
                        record.to.insert(next);
                    }
                }
                SemanticTerminator::Branch {
                    true_target,
                    false_target,
                    ..
                } => {
                    record.is_jump = true;
                    record.is_conditional = true;
                    if let Some(address) = semantic_expression_u64(true_target) {
                        record.to.insert(address);
                    }
                    if let Some(address) = semantic_expression_u64(false_target) {
                        record.to.insert(address);
                    }
                }
                SemanticTerminator::Trap => {
                    record.is_trap = true;
                }
                SemanticTerminator::Call { does_return, .. } => {
                    record.is_call = true;
                    if does_return.unwrap_or(true) {
                        if let Some(next) = next_block_address {
                            record.to.insert(next);
                        }
                    }
                }
                SemanticTerminator::FallThrough => {
                    if let Some(next) = next_block_address {
                        record.is_jump = true;
                        record.to.insert(next);
                    }
                }
                SemanticTerminator::Unreachable => {}
            }
        }
        record.edges = record.successors().len();
        graph.insert_instruction(record);
    }
}

fn semantic_expression_u64(expression: &SemanticExpression) -> Option<u64> {
    match expression {
        SemanticExpression::Const { value, .. } => (*value).try_into().ok(),
        _ => None,
    }
}

fn architecture_from_cpu(cpu: &SemanticCpu) -> Result<Architecture, LifterError> {
    match cpu.kind() {
        Some(crate::semantics::SemanticCpuKind::I386) => Ok(Architecture::I386),
        Some(crate::semantics::SemanticCpuKind::Amd64) => Ok(Architecture::AMD64),
        Some(crate::semantics::SemanticCpuKind::Arm64) => Ok(Architecture::ARM64),
        Some(crate::semantics::SemanticCpuKind::Cil) => Ok(Architecture::CIL),
        None => Err(LifterError::Io(Error::other(
            "lifter backend requires a built-in semantic CPU kind",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{Lifter, LifterBackend};
    use crate::Configuration;
    use crate::semantics::{
        Semantic, SemanticAbi, SemanticAbiKind, SemanticCpu, SemanticCpuKind, SemanticEffect,
        SemanticExpression, SemanticLocation, SemanticStatus, SemanticTerminator, Semantics,
    };

    #[test]
    fn default_backend_resolves_to_llvm() {
        let lifter = Lifter::new(
            SemanticCpu::from_kind(SemanticCpuKind::Amd64).expect("cpu"),
            Configuration::default(),
            LifterBackend::Default,
            None,
        )
        .expect("lifter");
        assert_eq!(lifter.backend(), LifterBackend::Llvm);
    }

    #[test]
    fn created_function_builder_replays_named_blocks() {
        let cpu = SemanticCpu::from_kind(SemanticCpuKind::I386).expect("cpu");
        let abi = SemanticAbi::from_kind(SemanticAbiKind::Stdcall, &cpu).expect("stdcall abi");
        let lifter =
            Lifter::new(cpu, Configuration::default(), LifterBackend::Llvm, None).expect("lifter");
        let function = lifter
            .create_function("add_one", Some(&abi))
            .expect("created function");

        let entry = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Const { value: 1, bits: 32 },
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        };
        let exit = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };

        function
            .lift_block_semantics(
                &Semantics {
                    semantics: vec![entry],
                    data: Vec::new(),
                },
                Some("entry"),
            )
            .expect("entry block");
        function
            .lift_block_semantics(
                &Semantics {
                    semantics: vec![exit],
                    data: Vec::new(),
                },
                Some("exit"),
            )
            .expect("exit block");
        function.optimize_cfg().expect("function cfg");
        function.optimize_dce().expect("function dce");
        lifter.optimize_mem2reg().expect("module mem2reg");

        let functions = lifter.functions().expect("functions");
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name(), "add_one");
        let blocks = functions[0].blocks();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].name(), "entry");
        assert_eq!(blocks[1].name(), "exit");

        let text = lifter.ir();
        assert!(text.contains("@add_one("));
        assert!(text.contains("entry:"));
    }

    #[test]
    fn created_function_body_semantics_uses_builtin_abi_arguments_for_signature() {
        let cpu = SemanticCpu::from_kind(SemanticCpuKind::I386).expect("cpu");
        let abi = SemanticAbi::from_kind(SemanticAbiKind::Fastcall, &cpu).expect("fastcall abi");
        let lifter =
            Lifter::new(cpu, Configuration::default(), LifterBackend::Llvm, None).expect("lifter");
        let function = lifter
            .create_function("add_one", Some(&abi))
            .expect("created function");

        let body = Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Set {
                dst: SemanticLocation::Register {
                    name: "eax".to_string(),
                    bits: 32,
                },
                expression: SemanticExpression::Binary {
                    op: crate::semantics::SemanticOperationBinary::Add,
                    left: Box::new(SemanticExpression::Read(Box::new(
                        SemanticLocation::Register {
                            name: "ecx".to_string(),
                            bits: 32,
                        },
                    ))),
                    right: Box::new(SemanticExpression::Const { value: 1, bits: 32 }),
                    bits: 32,
                },
            }],
            terminator: SemanticTerminator::Return { expression: None },
            diagnostics: Vec::new(),
        };

        function
            .lift_function_semantics(&Semantics {
                semantics: vec![body],
                data: Vec::new(),
            })
            .expect("function semantics");

        let ir = function.ir().expect("function ir");
        assert!(ir.contains("define i32 @add_one(i32 %0)"));
        assert!(!ir.contains("movl %ecx, $0"));
        assert!(ir.contains("ret i32 %abi_ret"));
    }

    #[test]
    fn created_functions_support_direct_semantic_calls() {
        let cpu = SemanticCpu::from_kind(SemanticCpuKind::I386).expect("cpu");
        let fastcall =
            SemanticAbi::from_kind(SemanticAbiKind::Fastcall, &cpu).expect("fastcall abi");
        let stdcall = SemanticAbi::from_kind(SemanticAbiKind::Stdcall, &cpu).expect("stdcall abi");
        let lifter =
            Lifter::new(cpu, Configuration::default(), LifterBackend::Llvm, None).expect("lifter");

        let add_two = lifter
            .create_function("add_two", Some(&fastcall))
            .expect("created function");
        add_two
            .lift_function_semantics(&Semantics {
                semantics: vec![Semantic {
                    version: 1,
                    status: SemanticStatus::Complete,
                    abi: None,
                    encoding: None,
                    temporaries: Vec::new(),
                    effects: vec![SemanticEffect::Set {
                        dst: SemanticLocation::Register {
                            name: "eax".to_string(),
                            bits: 32,
                        },
                        expression: SemanticExpression::Binary {
                            op: crate::semantics::SemanticOperationBinary::Add,
                            left: Box::new(SemanticExpression::Read(Box::new(
                                SemanticLocation::Register {
                                    name: "ecx".to_string(),
                                    bits: 32,
                                },
                            ))),
                            right: Box::new(SemanticExpression::Read(Box::new(
                                SemanticLocation::Register {
                                    name: "edx".to_string(),
                                    bits: 32,
                                },
                            ))),
                            bits: 32,
                        },
                    }],
                    terminator: SemanticTerminator::Return { expression: None },
                    diagnostics: Vec::new(),
                }],
                data: Vec::new(),
            })
            .expect("add_two semantics");

        let main = lifter
            .create_function("main", Some(&stdcall))
            .expect("created function");
        main.lift_function_semantics(&Semantics {
            semantics: vec![
                Semantic {
                    version: 1,
                    status: SemanticStatus::Complete,
                    abi: None,
                    encoding: None,
                    temporaries: Vec::new(),
                    effects: vec![
                        SemanticEffect::Set {
                            dst: SemanticLocation::Register {
                                name: "ecx".to_string(),
                                bits: 32,
                            },
                            expression: SemanticExpression::Const { value: 1, bits: 32 },
                        },
                        SemanticEffect::Set {
                            dst: SemanticLocation::Register {
                                name: "edx".to_string(),
                                bits: 32,
                            },
                            expression: SemanticExpression::Const { value: 1, bits: 32 },
                        },
                    ],
                    terminator: SemanticTerminator::Call {
                        target: SemanticExpression::Function {
                            name: "add_two".to_string(),
                            bits: 32,
                        },
                        return_target: None,
                        does_return: Some(true),
                    },
                    diagnostics: Vec::new(),
                },
                Semantic {
                    version: 1,
                    status: SemanticStatus::Complete,
                    abi: None,
                    encoding: None,
                    temporaries: Vec::new(),
                    effects: Vec::new(),
                    terminator: SemanticTerminator::Return { expression: None },
                    diagnostics: Vec::new(),
                },
            ],
            data: Vec::new(),
        })
        .expect("main semantics");

        lifter.optimize_mem2reg().expect("mem2reg");
        lifter.optimize_sroa().expect("sroa");
        lifter.optimize_instcombine().expect("instcombine");
        lifter.optimize_gvn().expect("gvn");
        lifter.optimize_dce().expect("dce");

        let ir = lifter.ir();
        assert!(ir.contains("define i32 @add_two(i32 %0, i32 %1)"));
        assert!(ir.contains("define i32 @main()"));
        assert!(ir.contains("call i32 @add_two(i32 1, i32 1)"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn vex_reports_unsupported_llvm_capabilities() {
        let lifter = Lifter::new(
            SemanticCpu::from_kind(SemanticCpuKind::Amd64).expect("cpu"),
            Configuration::default(),
            LifterBackend::Vex,
            None,
        )
        .expect("lifter");
        assert!(lifter.bitcode().is_err());
        assert!(lifter.optimize_mem2reg().is_err());
        assert!(lifter.create_function("builder", None).is_err());
        assert!(lifter.functions().is_err());
    }
}
