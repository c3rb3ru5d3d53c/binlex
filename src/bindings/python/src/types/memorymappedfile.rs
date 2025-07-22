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

use pyo3::prelude::*;
use pyo3::exceptions;
use pyo3::types::PyMemoryView;
use binlex::types::MemoryMappedFile as InnerMemoryMappedFile;
use pyo3::ffi;
use std::os::raw::c_char;

#[pyclass]
pub struct MemoryMappedFile {
    pub inner: InnerMemoryMappedFile,
}

#[pymethods]
impl MemoryMappedFile {
    #[new]
    #[pyo3(text_signature = "(path, cache)")]
    pub fn new(path: &str, cache: bool) -> PyResult<Self> {
        let path = std::path::PathBuf::from(path);
        let inner = InnerMemoryMappedFile::new(path, cache)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;
        Ok(MemoryMappedFile { inner })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn is_cached(&self) -> bool {
        self.inner.is_cached()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn path(&self) -> String {
        self.inner.path()
    }

    #[pyo3(text_signature = "($self, data)")]
    pub fn write(&mut self, data: &[u8]) -> PyResult<u64> {
        let mut reader = std::io::Cursor::new(data);
        self.inner
            .write(&mut reader)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))
    }

    #[pyo3(text_signature = "($self, length)")]
    pub fn write_padding(&mut self, length: usize) -> PyResult<()> {
        self.inner
            .write_padding(length)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn seek_to_end(&mut self) -> PyResult<u64> {
        self.inner
            .seek_to_end()
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))
    }

    #[pyo3(text_signature = "($self, offset)")]
    pub fn seek(&mut self, offset: u64) -> PyResult<u64> {
        self.inner
            .seek(offset)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn size(&self) -> PyResult<u64> {
        self.inner
            .size()
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn mmap<'py>(&'py mut self, py: Python<'py>) -> PyResult<Py<PyMemoryView>> {
        let mmap = self
            .inner
            .mmap()
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;
        let data = &mmap[..];
        let ptr = data.as_ptr() as *mut c_char;
        let len = data.len() as ffi::Py_ssize_t;
        unsafe {
            let memview_ptr = ffi::PyMemoryView_FromMemory(ptr, len, ffi::PyBUF_READ);
            if memview_ptr.is_null() {
                Err(PyErr::fetch(py))
            } else {
                Ok(Py::from_owned_ptr(py, memview_ptr))
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn mmap_mut<'py>(&'py mut self, py: Python<'py>) -> PyResult<Py<PyMemoryView>> {
        let mmap = self
            .inner
            .mmap_mut()
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;
        let data = &mmap[..];
        let ptr = data.as_ptr() as *mut c_char;
        let len = data.len() as ffi::Py_ssize_t;
        unsafe {
            let memview_ptr = ffi::PyMemoryView_FromMemory(ptr, len, ffi::PyBUF_WRITE);
            if memview_ptr.is_null() {
                Err(PyErr::fetch(py))
            } else {
                Ok(Py::from_owned_ptr(py, memview_ptr))
            }
        }
    }
}

#[pymodule]
#[pyo3(name = "memorymappedfile")]
pub fn memorymappedfile_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MemoryMappedFile>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.types.memorymappedfile", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.types.memorymappedfile")?;
    Ok(())
}

