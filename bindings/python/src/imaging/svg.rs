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

use crate::global::Config;
use crate::hashing::{AHash, DHash, PHash};
use crate::imaging::palette::Palette;
use binlex::imaging::SVG as InnerSVG;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::sync::{Arc, Mutex};

/// Render bytes into an SVG document.
#[pyclass]
pub struct SVG {
    pub(crate) inner: Arc<Mutex<InnerSVG>>,
}

impl SVG {
    pub(crate) fn from_inner(inner: InnerSVG) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl SVG {
    #[new]
    #[pyo3(signature = (data, palette, config, cell_size=1, fixed_width=16))]
    #[pyo3(text_signature = "(data, palette, config, cell_size=1, fixed_width=16)")]
    /// Create an SVG renderer for the provided bytes and palette.
    pub fn new(
        py: Python,
        data: Py<PyBytes>,
        palette: Py<Palette>,
        config: Py<Config>,
        cell_size: usize,
        fixed_width: usize,
    ) -> Self {
        let inner_data = data.bind(py).as_bytes();
        let inner_palette = palette.borrow(py).inner.lock().unwrap().clone();
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        Self {
            inner: Arc::new(Mutex::new(InnerSVG::with_options(
                inner_data,
                inner_palette,
                cell_size,
                fixed_width,
                inner_config,
            ))),
        }
    }

    #[pyo3(text_signature = "($self, key, value)")]
    /// Attach a metadata entry to the SVG document.
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.inner.lock().unwrap().add_metadata(key, value)
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the rendered SVG document as a string.
    pub fn to_string(&self) -> String {
        self.inner.lock().unwrap().to_string()
    }

    #[allow(clippy::useless_conversion)]
    #[pyo3(text_signature = "($self, file_path)")]
    /// Write the rendered SVG document to `file_path`.
    pub fn write(&self, file_path: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .write(&file_path)
            .map_err(|e| PyErr::new::<PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Print the rendered image as ANSI-colored terminal output.
    pub fn print(&self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .print()
            .map_err(|e| PyErr::new::<PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Print the SVG document to stdout.
    pub fn print_svg(&self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .print_svg()
            .map_err(|e| PyErr::new::<PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sha256(&self) -> Option<String> {
        self.inner.lock().unwrap().sha256()
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
    pub fn ahash(&self) -> Option<AHash> {
        let inner = self.inner.lock().unwrap();
        inner.ahash()?;
        Some(AHash::new(inner.png_bytes().ok()?))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dhash(&self) -> Option<DHash> {
        let inner = self.inner.lock().unwrap();
        inner.dhash()?;
        Some(DHash::new(inner.png_bytes().ok()?))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn phash(&self) -> Option<PHash> {
        let inner = self.inner.lock().unwrap();
        inner.phash()?;
        Some(PHash::new(inner.png_bytes().ok()?))
    }

    /// Return the SVG document when converted to a string.
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
