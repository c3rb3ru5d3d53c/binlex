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

use crate::types::memorymappedfile::MemoryMappedFile;
use crate::Architecture;
use crate::Config;
use binlex::formats::ELF as InnerELF;
use pyo3::prelude::*;
use pyo3::types::PyType;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass(unsendable)]
pub struct ELF {
    pub inner: Arc<Mutex<InnerELF>>,
}

#[pymethods]
impl ELF {
    #[new]
    #[pyo3(text_signature = "(path, config)")]
    pub fn new(py: Python, path: String, config: Py<Config>) -> Result<Self, Error> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerELF::new(path, inner_config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[classmethod]
    #[pyo3(text_signature = "(bytes, config)")]
    pub fn from_bytes(
        _: &Bound<'_, PyType>,
        py: Python,
        bytes: Vec<u8>,
        config: Py<Config>,
    ) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerELF::from_bytes(bytes, inner_config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn architecture(&self) -> Architecture {
        return Architecture::from_value(self.inner.lock().unwrap().architecture() as u16);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        self.inner
            .lock()
            .unwrap()
            .executable_virtual_address_ranges()
    }

    #[pyo3(text_signature = "($self, relative_virtual_address)")]
    pub fn relative_virtual_address_to_virtual_address(
        &self,
        relative_virtual_address: u64,
    ) -> u64 {
        self.inner
            .lock()
            .unwrap()
            .relative_virtual_address_to_virtual_address(relative_virtual_address)
    }

    #[pyo3(text_signature = "($self, file_offset)")]
    pub fn file_offset_to_virtual_address(&self, file_offset: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .file_offset_to_virtual_address(file_offset)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entrypoint_virtual_addresses(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().entrypoint_virtual_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entrypoint_virtual_address(&self) -> u64 {
        self.inner.lock().unwrap().entrypoint_virtual_address()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn image(&self, py: Python<'_>) -> PyResult<Py<MemoryMappedFile>> {
        let result = self
            .inner
            .lock()
            .unwrap()
            .image()
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        let py_memory_mapped_file = Py::new(py, MemoryMappedFile { inner: result })?;
        Ok(py_memory_mapped_file)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh(&self) -> Option<String> {
        self.inner.lock().unwrap().tlsh()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sha256(&self) -> Option<String> {
        self.inner.lock().unwrap().sha256()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn size(&self) -> u64 {
        self.inner.lock().unwrap().size()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn export_virtual_addresses(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().export_virtual_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn file_json(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .file_json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }
}

#[pymodule]
#[pyo3(name = "elf")]
pub fn elf_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ELF>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.formats.elf", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.formats.elf")?;
    Ok(())
}
