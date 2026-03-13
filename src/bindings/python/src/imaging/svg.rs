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

use crate::imaging::palette::Palette;
use binlex::imaging::SVG as InnerSVG;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::sync::{Arc, Mutex};

#[pyclass]
pub struct SVG {
    inner: Arc<Mutex<InnerSVG>>,
}

#[pymethods]
impl SVG {
    #[new]
    #[pyo3(signature = (data, palette, cell_size=1, fixed_width=16))]
    #[pyo3(text_signature = "(data, palette, cell_size=1, fixed_width=16)")]
    pub fn new(
        py: Python,
        data: Py<PyBytes>,
        palette: Py<Palette>,
        cell_size: usize,
        fixed_width: usize,
    ) -> Self {
        let inner_data = data.bind(py).as_bytes();
        let inner_palette = palette.borrow(py).inner.lock().unwrap().clone();
        Self {
            inner: Arc::new(Mutex::new(InnerSVG::new_with_options(
                inner_data,
                inner_palette,
                cell_size,
                fixed_width,
            ))),
        }
    }

    #[pyo3(text_signature = "($self, key, value)")]
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.inner.lock().unwrap().add_metadata(key, value)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_string(&self) -> String {
        self.inner.lock().unwrap().to_string()
    }

    #[allow(clippy::useless_conversion)]
    #[pyo3(text_signature = "($self, file_path)")]
    pub fn write(&self, file_path: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .write(&file_path)
            .map_err(|e| PyErr::new::<PyRuntimeError, _>(e.to_string()))
    }

    pub fn __str__(&self) -> String {
        self.to_string()
    }
}

#[pymodule]
#[pyo3(name = "svg")]
pub fn svg_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SVG>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.imaging.svg", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.imaging.svg")?;
    Ok(())
}
