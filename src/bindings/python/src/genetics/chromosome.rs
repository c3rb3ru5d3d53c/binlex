use pyo3::prelude::*;
use pyo3::Py;
use binlex::genetics::Chromosome as InnerChromosome;
use crate::genetics::AllelePair;
use std::sync::Arc;
use std::sync::Mutex;
use crate::config::Config;
use pyo3::types::PyBytes;
use pyo3::exceptions::PyRuntimeError;

#[pyclass]
pub struct Chromosome {
    pub inner: Arc<Mutex<InnerChromosome>>,
}

#[pymethods]
impl Chromosome {
    #[new]
    #[pyo3(text_signature = "(pattern, config)")]
    pub fn new(py: Python, pattern: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerChromosome::new(pattern, inner_config.clone())?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn allelepairs(&self) -> Vec<AllelePair> {
        let mut result = Vec::<AllelePair>::new();
        for allelepair in self.inner.lock().unwrap().allelepairs(){
            result.push(AllelePair{
                inner: Arc::new(Mutex::new(allelepair))
            });
        }
        result
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_mutations(&self) -> usize {
        self.inner.lock().unwrap().number_of_mutations()
    }

    #[pyo3(text_signature = "($self, pattern)")]
    pub fn mutate(&mut self, pattern: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .mutate(pattern)
            .map_err(|error| PyRuntimeError::new_err(format!("{}", error)))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn pattern(&self) -> String {
        self.inner.lock().unwrap().pattern()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn feature(&self) -> Vec<u8> {
        self.inner.lock().unwrap().feature()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh(&self) -> Option<String> {
        self.inner.lock().unwrap().tlsh()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn minhash(&self) -> Option<String> {
        self.inner.lock().unwrap().minhash()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sha256(&self) -> Option<String> {
        self.inner.lock().unwrap().sha256()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn normalized(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new_bound(py, &self.inner.lock().unwrap().normalized()).into()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner
            .lock()
            .unwrap()
            .print();
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import_bound("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self, _py: Python) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }
}

#[pymodule]
#[pyo3(name = "chromosome")]
pub fn chromosome_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Chromosome>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.genetics.chromosome", m)?;
    m.setattr("__name__", "binlex.genetics.chromosome")?;
    Ok(())
}
