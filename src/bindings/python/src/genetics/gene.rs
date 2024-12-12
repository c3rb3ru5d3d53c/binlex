use pyo3::prelude::*;
use binlex::genetics::Gene as InnerGene;
use std::sync::Arc;
use std::sync::Mutex;

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
    pub fn from_u8(v: u8) -> PyResult<Self> {
        let inner = InnerGene::from_u8(v);
        Ok(Self{inner: Arc::new(Mutex::new(inner))})
    }

    #[pyo3(text_signature = "(pattern, config)")]
    pub fn to_char(&self) -> String {
        self.inner.lock().unwrap().to_char()
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
