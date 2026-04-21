use crate::controlflow::{Block, Function, Instruction};
use crate::Config;
use binlex::io::Stderr;
use binlex::lifters::vex::Lifter as InnerLifter;
use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

#[pyclass(unsendable)]
pub struct Lifter {
    pub config: binlex::Config,
    pub inner: Arc<Mutex<InnerLifter>>,
}

#[pymethods]
impl Lifter {
    #[new]
    #[pyo3(text_signature = "(config)")]
    pub fn new(py: Python<'_>, config: Py<Config>) -> Self {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerLifter::new(inner_config.clone());
        Self {
            config: inner_config,
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
                    format!("vex lift instruction failed: {}", err),
                );
                false
            }
            Err(err) => {
                Stderr::print_debug(
                    &self.config,
                    format!("vex lift instruction failed: {}", err),
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
                Stderr::print_debug(&self.config, format!("vex lift block failed: {}", err));
                false
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("vex lift block failed: {}", err));
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
                Stderr::print_debug(&self.config, format!("vex lift function failed: {}", err));
                false
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("vex lift function failed: {}", err));
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

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymodule]
#[pyo3(name = "vex")]
pub fn vex_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Lifter>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.lifters.vex", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.lifters.vex")?;
    Ok(())
}
