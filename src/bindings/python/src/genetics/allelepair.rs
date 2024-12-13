use pyo3::prelude::*;
use pyo3::Py;
use binlex::genetics::AllelePair as InnerAllelePair;
use std::sync::Arc;
use std::sync::Mutex;
use crate::genetics::Gene;

#[pyclass]
pub struct AllelePair {
    pub inner: Arc<Mutex<InnerAllelePair>>,
}

#[pymethods]
impl AllelePair {
    #[new]
    #[pyo3(text_signature = "(low, high)")]
    pub fn new(py: Python, low: Py<Gene>, high: Py<Gene>) -> PyResult<Self> {
        let high_binding = high.borrow(py);
        let high_inner = high_binding.inner.lock().unwrap().clone();
        let low_binding = low.borrow(py);
        let low_inner = low_binding.inner.lock().unwrap().clone();
        let inner = InnerAllelePair::new(high_inner, low_inner);
        Ok(Self{
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_mutations(&self) -> usize {
        self.inner.lock().unwrap().number_of_mutations()
    }

    #[pyo3(text_signature = "($self, low, high)")]
    pub fn mutate(&mut self, py: Python, low: Py<Gene>, high: Py<Gene>) {
        let high_binding = high.borrow(py);
        let high_inner = high_binding.inner.lock().unwrap().clone();
        let low_binding = low.borrow(py);
        let low_inner = low_binding.inner.lock().unwrap().clone();
        self.inner.lock().unwrap().mutate(high_inner, low_inner);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn genes(&self) -> Vec<Gene> {
        let mut result = Vec::<Gene>::new();
        result.push(self.low());
        result.push(self.low());
        result
    }

    #[staticmethod]
    #[pyo3(text_signature = "(pair)")]
    pub fn from_string(pair: String) -> PyResult<Self> {
        let inner = InnerAllelePair::from_string(pair)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn low(&self) -> Gene {
        let low = self.inner.lock().unwrap().low;
        return Gene {
            inner: Arc::new(Mutex::new(low))
        };
    }

    #[pyo3(text_signature = "($self)")]
    pub fn high(&self) -> Gene {
        let high = self.inner.lock().unwrap().high;
        return Gene {
            inner: Arc::new(Mutex::new(high))
        };
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_string(&self) -> String {
        self.inner.lock().unwrap().to_string()
    }

    pub fn __str__(&self) -> String {
        self.to_string()
    }
}


#[pymodule]
#[pyo3(name = "allelepair")]
pub fn allelepair_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AllelePair>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.genetics.allelepair", m)?;
    m.setattr("__name__", "binlex.genetics.allelepair")?;
    Ok(())
}
