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
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::formats::File;
use crate::formats::Symbol as PySymbol;
use crate::hashing::{SSDeep, SHA256, TLSH};
use crate::Architecture;
use crate::Configuration;
use binlex::formats::COFF as InnerCOFF;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::BTreeMap;
use std::io::Error;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass(unsendable)]
pub struct COFF {
    pub inner: Arc<Mutex<InnerCOFF>>,
}

#[pymethods]
impl COFF {
    #[new]
    #[pyo3(text_signature = "(data, config)")]
    pub fn new(py: Python, data: Vec<u8>, config: Py<Configuration>) -> Result<Self, Error> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerCOFF::new(data, inner_config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn architecture(&self) -> Architecture {
        Architecture::from_value(self.inner.lock().unwrap().architecture() as u16)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn executable_file_offset_ranges(&self) -> BTreeMap<u64, u64> {
        self.inner.lock().unwrap().executable_file_offset_ranges()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bytes(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.lock().unwrap().bytes()).unbind()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn size(&self) -> u64 {
        self.inner.lock().unwrap().size()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn symbols(&self, py: Python<'_>) -> PyResult<Vec<Py<PySymbol>>> {
        self.inner
            .lock()
            .unwrap()
            .symbols()
            .into_values()
            .map(|symbol| Py::new(py, PySymbol::from_inner(symbol)))
            .collect()
    }

    #[pyo3(text_signature = "($self, offset)")]
    pub fn file_offset_to_symbol(
        &self,
        py: Python<'_>,
        file_offset: u64,
    ) -> PyResult<Option<Py<PySymbol>>> {
        self.inner
            .lock()
            .unwrap()
            .file_offset_to_symbol(file_offset)
            .map(|symbol| Py::new(py, PySymbol::from_inner(symbol)))
            .transpose()
    }

    #[pyo3(text_signature = "($self, name)")]
    pub fn symbol_name_to_file_offset(&self, name: &str) -> Option<u64> {
        self.inner.lock().unwrap().symbol_name_to_file_offset(name)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh(&self) -> Option<TLSH> {
        self.inner.lock().unwrap().tlsh().map(|hash| TLSH {
            bytes: hash.bytes.into_owned(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sha256(&self) -> Option<SHA256> {
        self.inner.lock().unwrap().sha256().map(|hash| SHA256 {
            bytes: hash.bytes.into_owned(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn ssdeep(&self) -> Option<SSDeep> {
        self.inner.lock().unwrap().ssdeep().map(|hash| SSDeep {
            bytes: hash.bytes.into_owned(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn file(&self, py: Python<'_>) -> PyResult<Py<File>> {
        let config = self.inner.lock().unwrap().config.clone();
        let file = self.inner.lock().unwrap().file().clone();
        Py::new(
            py,
            File {
                inner: file,
                config: Py::new(
                    py,
                    Configuration {
                        inner: Arc::new(Mutex::new(config)),
                    },
                )?,
            },
        )
    }
}

#[pymodule]
#[pyo3(name = "coff")]
pub fn coff_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<COFF>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.formats.coff", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.formats.coff")?;
    Ok(())
}
