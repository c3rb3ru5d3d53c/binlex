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

use crate::config::Config;
use crate::hashing::{AHash, DHash, MinHash32, PHash, SHA256, TLSH};
use crate::imaging::palette::Palette;
use binlex::imaging::Terminal as InnerTerminal;
use pyo3::Py;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::{Arc, Mutex};

/// Render bytes as ANSI-colored terminal output.
#[pyclass]
pub struct Terminal {
    inner: Arc<Mutex<InnerTerminal>>,
}

impl Terminal {
    pub(crate) fn from_inner(inner: InnerTerminal) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl Terminal {
    #[new]
    #[pyo3(signature = (data, palette, config, cell_size=1, fixed_width=16))]
    #[pyo3(text_signature = "(data, palette, config, cell_size=1, fixed_width=16)")]
    /// Create a terminal renderer for the provided bytes and palette.
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
            inner: Arc::new(Mutex::new(InnerTerminal::with_options(
                inner_data,
                inner_palette,
                cell_size,
                fixed_width,
                inner_config,
            ))),
        }
    }

    #[pyo3(text_signature = "($self)")]
    /// Print the rendered terminal output to stdout.
    pub fn print(&self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .print()
            .map_err(|e| PyErr::new::<PyRuntimeError, _>(e.to_string()))
    }

    #[staticmethod]
    #[pyo3(text_signature = "(r, g, b)")]
    /// Convert an RGB triplet into the nearest ANSI 256-color index.
    pub fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
        InnerTerminal::rgb_to_ansi256(r, g, b)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sha256(&self) -> Option<SHA256> {
        self.inner.lock().unwrap().sha256().map(|hash| SHA256 {
            bytes: hash.bytes.into_owned(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh(&self) -> Option<TLSH> {
        self.inner.lock().unwrap().tlsh().map(|hash| TLSH {
            bytes: hash.bytes.into_owned(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn minhash(&self) -> Option<MinHash32> {
        self.inner.lock().unwrap().minhash().map(|hash| MinHash32 {
            bytes: hash.bytes.into_owned(),
            num_hashes: hash.num_hashes,
            shingle_size: hash.shingle_size,
            seed: hash.seed,
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn ahash(&self) -> Option<AHash> {
        self.inner
            .lock()
            .unwrap()
            .ahash()
            .map(|hash| AHash::new(hash.bytes.into_owned()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dhash(&self) -> Option<DHash> {
        self.inner
            .lock()
            .unwrap()
            .dhash()
            .map(|hash| DHash::new(hash.bytes.into_owned()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn phash(&self) -> Option<PHash> {
        self.inner
            .lock()
            .unwrap()
            .phash()
            .map(|hash| PHash::new(hash.bytes.into_owned()))
    }
}

#[pymodule]
#[pyo3(name = "terminal")]
pub fn terminal_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Terminal>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.imaging.terminal", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.imaging.terminal")?;
    Ok(())
}
