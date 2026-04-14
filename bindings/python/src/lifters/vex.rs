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

use crate::Architecture;
use crate::Config;
use binlex::lifters::vex::Lifter as InnerLifter;
use binlex::lifters::vex::LifterJsonDeserializer as InnerLifterJsonDeserializer;
use pyo3::Py;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::{Arc, Mutex};

#[pyclass]
pub struct LifterJsonDeserializer {
    pub inner: Arc<Mutex<InnerLifterJsonDeserializer>>,
}

#[pymethods]
impl LifterJsonDeserializer {
    #[new]
    #[pyo3(text_signature = "(string, config)")]
    pub fn new(py: Python, string: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerLifterJsonDeserializer::new(string, inner_config)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn architecture(&self) -> PyResult<Architecture> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .architecture()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Architecture { inner })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let bytes = self
            .inner
            .lock()
            .unwrap()
            .bytes()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(PyBytes::new(py, &bytes).unbind())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn ir_string(&self) -> String {
        self.inner.lock().unwrap().json.ir.clone()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn ir(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .ir()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json()?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn process(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json = self
            .inner
            .lock()
            .unwrap()
            .process()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        let json_str =
            serde_json::to_string(&json).map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        let json_module = py.import("json")?;
        Ok(json_module.call_method1("loads", (json_str,))?.into())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print()
    }

    pub fn __str__(&self) -> PyResult<String> {
        self.json()
    }
}

#[pyclass(unsendable)]
pub struct Lifter {
    pub inner: Arc<Mutex<InnerLifter>>,
}

#[pymethods]
impl Lifter {
    #[new]
    #[pyo3(text_signature = "(architecture, bytes, address, config)")]
    pub fn new(
        py: Python,
        architecture: &Architecture,
        bytes: &Bound<'_, PyBytes>,
        address: u64,
        config: Py<Config>,
    ) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerLifter::new(architecture.inner, bytes.as_bytes(), address, inner_config)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn architecture(&self) -> Architecture {
        let inner = self.inner.lock().unwrap().architecture();
        Architecture { inner }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bytes(&self, py: Python) -> Py<PyBytes> {
        let bytes = self.inner.lock().unwrap().bytes().to_vec();
        PyBytes::new(py, &bytes).unbind()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn ir(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .ir()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json()?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self) -> PyResult<String> {
        let json = self
            .inner
            .lock()
            .unwrap()
            .process()
            .map_err(|err| PyRuntimeError::new_err(format!("{:?}", err)))?;
        serde_json::to_string(&json).map_err(|err| PyRuntimeError::new_err(err.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __str__(&self) -> PyResult<String> {
        self.json()
    }
}

#[pymodule]
#[pyo3(name = "vex")]
pub fn vex_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Lifter>()?;
    m.add_class::<LifterJsonDeserializer>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.lifters.vex", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.lifters.vex")?;
    Ok(())
}
