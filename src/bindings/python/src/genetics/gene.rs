use pyo3::prelude::*;
use binlex::genetics::Gene as InnerGene;
use std::sync::Arc;
use std::sync::Mutex;
use pyo3::exceptions::PyRuntimeError;

#[pyclass]
#[derive(Debug, Clone)]
pub struct Gene {
    pub inner: Arc<Mutex<InnerGene>>,
}

#[pymethods]
impl Gene {
    #[staticmethod]
    #[pyo3(text_signature = "(c)")]
    pub fn from_char(c: char) -> PyResult<Self> {
        let inner = InnerGene::from_char(c)?;
        Ok(Self { inner: Arc::new(Mutex::new(inner)) })
    }

    #[staticmethod]
    #[pyo3(text_signature = "(pattern, config)")]
    pub fn from_value(v: u8) -> PyResult<Self> {
        let inner = InnerGene::from_value(v);
        Ok(Self{inner: Arc::new(Mutex::new(inner))})
    }

    #[staticmethod]
    #[pyo3(text_signature = "()")]
    pub fn from_wildcard() -> PyResult<Self> {
        let inner = InnerGene::from_wildcard();
        Ok(Self{inner: Arc::new(Mutex::new(inner))})
    }

    #[pyo3(text_signature = "($self, c)")]
    pub fn mutate(&mut self, c: char) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .mutate(c)
            .map_err(|error| PyRuntimeError::new_err(format!("{}", error)))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn wildcard(&self) -> Option<String> {
        self.inner.lock().unwrap().wildcard()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn is_wildcard(&self) -> bool {
        self.inner.lock().unwrap().is_wildcard()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn is_value(&self) -> bool {
        self.inner.lock().unwrap().is_value()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_char(&self) -> String {
        self.inner.lock().unwrap().to_char()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    pub fn __str__(&self) -> String {
        self.to_char()
    }
}


#[pymodule]
#[pyo3(name = "gene")]
pub fn gene_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Gene>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.genetics.gene", m)?;
    m.setattr("__name__", "binlex.genetics.genee")?;
    Ok(())
}
