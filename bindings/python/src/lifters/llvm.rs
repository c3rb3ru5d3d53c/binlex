use crate::controlflow::{Block, Function, Instruction};
use crate::lifters::llvm_abi::llvm_abi_init;
use crate::semantics::InstructionSemantics as PyInstructionSemantics;
use crate::Architecture;
use crate::Config;
use binlex::io::Stderr;
use binlex::lifters::llvm::Lifter as InnerLifter;
use pyo3::prelude::*;
use pyo3::wrap_pymodule;
use std::sync::{Arc, Mutex};

#[pyclass(unsendable)]
pub struct Lifter {
    pub config: binlex::Config,
    pub architecture: binlex::Architecture,
    pub inner: Arc<Mutex<InnerLifter>>,
}

#[pymethods]
impl Lifter {
    #[new]
    #[pyo3(text_signature = "(architecture, config)")]
    pub fn new(py: Python<'_>, architecture: Py<Architecture>, config: Py<Config>) -> Self {
        let inner_architecture = architecture.borrow(py).inner;
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerLifter::new(inner_architecture, inner_config.clone());
        Self {
            config: inner_config,
            architecture: inner_architecture,
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    #[pyo3(text_signature = "($self, instruction)")]
    pub fn lift_instruction(&self, py: Python<'_>, instruction: &Instruction) -> bool {
        match instruction.with_inner_instruction(py, |inner| {
            Ok(self.inner.lock().unwrap().lift_instruction(inner))
        }) {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                Stderr::print_debug(
                    &self.config,
                    format!("llvm lift instruction failed: {}", err),
                );
                false
            }
            Err(err) => {
                Stderr::print_debug(
                    &self.config,
                    format!("llvm lift instruction failed: {}", err),
                );
                false
            }
        }
    }

    #[pyo3(text_signature = "($self, block)")]
    pub fn lift_block(&self, py: Python<'_>, block: &Block) -> bool {
        match block.with_inner_block(py, |inner| Ok(self.inner.lock().unwrap().lift_block(inner))) {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                Stderr::print_debug(&self.config, format!("llvm lift block failed: {}", err));
                false
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm lift block failed: {}", err));
                false
            }
        }
    }

    #[pyo3(text_signature = "($self, function)")]
    pub fn lift_function(&self, py: Python<'_>, function: &Function) -> bool {
        match function.with_inner_function(py, |inner| {
            Ok(self.inner.lock().unwrap().lift_function(inner))
        }) {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                Stderr::print_debug(&self.config, format!("llvm lift function failed: {}", err));
                false
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm lift function failed: {}", err));
                false
            }
        }
    }

    #[pyo3(text_signature = "($self, semantics)")]
    pub fn lift_semantics(&self, _py: Python<'_>, semantics: &PyInstructionSemantics) -> bool {
        let semantics = semantics.inner.lock().unwrap().clone();
        match self.inner.lock().unwrap().lift_semantics(&semantics) {
            Ok(()) => true,
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm lift semantics failed: {}", err));
                false
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bitcode(&self) -> Vec<u8> {
        self.inner.lock().unwrap().bitcode()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn object(&self) -> Option<Vec<u8>> {
        match self.inner.lock().unwrap().object() {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm object failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn normalized(&self) -> Option<Self> {
        match self.inner.lock().unwrap().normalized() {
            Ok(inner) => Some(Self {
                config: self.config.clone(),
                architecture: self.architecture,
                inner: Arc::new(Mutex::new(inner)),
            }),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm normalize failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn mem2reg(&self) -> Option<Self> {
        match self.inner.lock().unwrap().mem2reg() {
            Ok(inner) => Some(Self {
                config: self.config.clone(),
                architecture: self.architecture,
                inner: Arc::new(Mutex::new(inner)),
            }),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm mem2reg failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn instcombine(&self) -> Option<Self> {
        match self.inner.lock().unwrap().instcombine() {
            Ok(inner) => Some(Self {
                config: self.config.clone(),
                architecture: self.architecture,
                inner: Arc::new(Mutex::new(inner)),
            }),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm instcombine failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn cfg(&self) -> Option<Self> {
        match self.inner.lock().unwrap().cfg() {
            Ok(inner) => Some(Self {
                config: self.config.clone(),
                architecture: self.architecture,
                inner: Arc::new(Mutex::new(inner)),
            }),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm cfg failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn gvn(&self) -> Option<Self> {
        match self.inner.lock().unwrap().gvn() {
            Ok(inner) => Some(Self {
                config: self.config.clone(),
                architecture: self.architecture,
                inner: Arc::new(Mutex::new(inner)),
            }),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm gvn failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sroa(&self) -> Option<Self> {
        match self.inner.lock().unwrap().sroa() {
            Ok(inner) => Some(Self {
                config: self.config.clone(),
                architecture: self.architecture,
                inner: Arc::new(Mutex::new(inner)),
            }),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm sroa failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dce(&self) -> Option<Self> {
        match self.inner.lock().unwrap().dce() {
            Ok(inner) => Some(Self {
                config: self.config.clone(),
                architecture: self.architecture,
                inner: Arc::new(Mutex::new(inner)),
            }),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm dce failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn verify(&self) -> Option<bool> {
        match self.inner.lock().unwrap().verify() {
            Ok(()) => Some(true),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm verify failed: {}", err));
                None
            }
        }
    }

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymodule]
#[pyo3(name = "llvm")]
pub fn llvm_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Lifter>()?;
    m.add_wrapped(wrap_pymodule!(llvm_abi_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.lifters.llvm", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.lifters.llvm")?;
    Ok(())
}
