use pyo3::prelude::*;
use std::collections::BTreeSet;
use binlex::controlflow::Instruction as InnerInstruction;
use crate::controlflow::Graph;
use std::sync::Mutex;
use std::sync::Arc;

#[pyclass]
pub struct Instruction {
    pub address: u64,
    pub cfg: Py<Graph>,
    inner: Arc<Mutex<Option<InnerInstruction>>>,
}

impl Instruction {
    fn with_inner_instruction<F, R>(&self, py: Python, f: F) -> PyResult<R>
    where
        F: FnOnce(&InnerInstruction) -> PyResult<R>,
    {
        let mut cache = self.inner.lock().unwrap();

        if cache.is_none() {
            let binding = self.cfg.borrow(py);
            let inner = binding.inner.lock().unwrap();

            #[allow(mutable_transmutes)]
            let inner_ref: _ = unsafe { std::mem::transmute(&*inner) };
            let inner_instruction = InnerInstruction::new(self.address, inner_ref);
            if inner_instruction.is_err() {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "instruction does not exist",
                ));
             }
            *cache = Some(inner_instruction.unwrap());
        }

        f(cache.as_ref().unwrap())
    }
}

#[pymethods]
impl Instruction {
    #[new]
    #[pyo3(text_signature = "(address, cfg)")]
    fn new(address: u64, cfg: Py<Graph>) -> PyResult<Self> {
        Ok(Self {
            address,
            cfg,
            inner: Arc::new(Mutex::new(None)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn blocks(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction.blocks())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn next(&self, py: Python) -> PyResult<Option<u64>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction.next())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction.to())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn functions(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction.functions())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn size(&self, py: Python) -> PyResult<usize> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction.size())
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import_bound("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self, py: Python) -> PyResult<String> {
        self.with_inner_instruction(py, |instruction| {
            instruction.json().map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
        })
    }

    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self, py: Python) -> PyResult<()> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.print()))
    }
}

#[pymodule]
#[pyo3(name = "instruction")]
pub fn instruction_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Instruction>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.controlflow.instruction", m)?;
    m.setattr("__name__", "binlex.controlflow.instruction")?;
    Ok(())
}
