// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::genetics::AllelePair;
use crate::Config;
use binlex::genetics::chromosome::HomologousChromosome as InnerHomologousChromosome;
use binlex::genetics::Chromosome as InnerChromosome;
use binlex::genetics::ChromosomeSimilarity as InnerChromosomeSimilarity;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass]
pub struct ChromosomeSimilarityScore {
    pub inner: Arc<Mutex<InnerChromosomeSimilarity>>,
}

#[pymethods]
impl ChromosomeSimilarityScore {
    #[pyo3(text_signature = "($self)")]
    pub fn minhash(&self) -> Option<f64> {
        self.inner.lock().unwrap().score().minhash()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh(&self) -> Option<f64> {
        self.inner.lock().unwrap().score().tlsh()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self, _py: Python) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }
}

#[pyclass]
pub struct HomologousChromosome {
    pub inner: Arc<Mutex<InnerHomologousChromosome>>,
}

#[pymethods]
impl HomologousChromosome {
    #[new]
    #[pyo3(text_signature = "($score, chromosome)")]
    pub fn new(py: Python, score: f64, chromosome: Py<Chromosome>) -> PyResult<Self> {
        let binding = chromosome.borrow(py);
        let inner_chromosome = binding.inner.lock().unwrap().clone();
        let inner_homologous_chromosome = InnerHomologousChromosome {
            score,
            chromosome: inner_chromosome,
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner_homologous_chromosome)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self, _py: Python) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }
}

#[pyclass]
pub struct ChromosomeSimilarity {
    pub inner: Arc<Mutex<InnerChromosomeSimilarity>>,
}

#[pymethods]
impl ChromosomeSimilarity {
    // #[new]
    // #[pyo3(signature = (minhash=None, tlsh=None))]
    // pub fn new(minhash: Option<f64>, tlsh: Option<u32>) -> Self {
    //     Self {
    //         inner: Arc::new(Mutex::new(InnerChromosomeSimilarity::new(minhash, tlsh))),
    //     }
    // }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self, _py: Python) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[getter]
    pub fn score(&self) -> ChromosomeSimilarityScore {
        ChromosomeSimilarityScore {
            inner: Arc::clone(&self.inner),
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import_bound("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }
}

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
        for allelepair in self.inner.lock().unwrap().allelepairs() {
            result.push(AllelePair {
                inner: Arc::new(Mutex::new(allelepair)),
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

    #[pyo3(text_signature = "($self, rhs)")]
    pub fn compare(&self, py: Python, rhs: Py<Chromosome>) -> Option<ChromosomeSimilarity> {
        let rhs_inner = rhs.borrow(py).inner.lock().unwrap().clone();
        let lhs_inner = self.inner.lock().unwrap().clone();
        let similarity = lhs_inner.compare(&rhs_inner)?;
        Some(ChromosomeSimilarity {
            inner: Arc::new(Mutex::new(similarity)),
        })
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
        self.inner.lock().unwrap().print();
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
        .set_item("binlex_bindings.binlex.genetics.chromosome", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.genetics.chromosome")?;
    Ok(())
}
