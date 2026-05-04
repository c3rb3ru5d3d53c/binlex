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

use binlex::controlflow::Reference as InnerReference;
use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct Reference {
    pub inner: InnerReference,
}

#[pymethods]
impl Reference {
    #[new]
    #[pyo3(text_signature = "(location, address)")]
    pub fn new(location: u64, address: u64) -> Self {
        Self {
            inner: InnerReference::new(location, address),
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn location(&self) -> u64 {
        self.inner.location
    }

    #[pyo3(text_signature = "($self)")]
    pub fn address(&self) -> u64 {
        self.inner.address
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("location", self.location())?;
        dict.set_item("address", self.address())?;
        Ok(dict.into())
    }

    pub fn __str__(&self, py: Python) -> PyResult<String> {
        let json = py.import("json")?;
        let value = self.to_dict(py)?;
        json.call_method1("dumps", (value,))?.extract()
    }
}
