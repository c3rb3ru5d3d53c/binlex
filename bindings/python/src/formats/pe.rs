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

use crate::formats::File;
use crate::formats::Image;
use crate::formats::Symbol as PySymbol;
use crate::hashing::{SSDeep, SHA256, TLSH};
use crate::imaging::Imaging;
use crate::Architecture;
use crate::Config;
use binlex::formats::pe::PE as InnerPe;
use pyo3::prelude::*;
use pyo3::types::PyType;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;
use std::sync::Mutex;

/// Parse and inspect a Portable Executable image.
#[pyclass(unsendable)]
pub struct PE {
    pub inner: Arc<Mutex<InnerPe>>,
}

#[pymethods]
impl PE {
    #[new]
    #[pyo3(text_signature = "(path, config)")]
    /// Open a PE image from `path`.
    pub fn new(py: Python, path: String, config: Py<Config>) -> Result<Self, Error> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerPe::new(path, inner_config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[classmethod]
    #[pyo3(text_signature = "(bytes, config)")]
    /// Parse a PE image from raw bytes in memory.
    pub fn from_bytes(
        _: &Bound<'_, PyType>,
        py: Python,
        bytes: Vec<u8>,
        config: Py<Config>,
    ) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerPe::from_bytes(bytes, inner_config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return whether the image contains a .NET/CLI header.
    pub fn is_dotnet(&self) -> bool {
        self.inner.lock().unwrap().is_dotnet()
    }

    #[pyo3(text_signature = "($self, virtual_address)")]
    /// Convert a virtual address to a relative virtual address.
    pub fn virtual_address_to_relative_virtual_address(&self, virtual_address: u64) -> u64 {
        self.inner
            .lock()
            .unwrap()
            .virtual_address_to_relative_virtual_address(virtual_address)
    }

    #[pyo3(text_signature = "($self, virtual_address)")]
    /// Convert a virtual address to a file offset, if mapped.
    pub fn virtual_address_to_file_offset(&self, virtual_address: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .virtual_address_to_file_offset(virtual_address)
    }

    #[pyo3(text_signature = "($self, relative_virtual_address)")]
    /// Convert a relative virtual address to a file offset, if mapped.
    pub fn relative_virtual_address_to_file_offset(
        &self,
        relative_virtual_address: u64,
    ) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .relative_virtual_address_to_file_offset(relative_virtual_address)
    }

    #[pyo3(text_signature = "($self, relative_virtual_address)")]
    /// Convert a relative virtual address to a virtual address.
    pub fn relative_virtual_address_to_virtual_address(
        &self,
        relative_virtual_address: u64,
    ) -> u64 {
        self.inner
            .lock()
            .unwrap()
            .relative_virtual_address_to_virtual_address(relative_virtual_address)
    }

    #[pyo3(text_signature = "($self, offset)")]
    /// Convert a file offset to a virtual address, if mapped.
    pub fn file_offset_to_virtual_address(&self, file_offset: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .file_offset_to_virtual_address(file_offset)
    }

    #[pyo3(text_signature = "($self, offset)")]
    /// Convert a file offset to a relative virtual address, if mapped.
    pub fn file_offset_to_relative_virtual_address(&self, file_offset: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .file_offset_to_relative_virtual_address(file_offset)
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the architecture of the PE image.
    pub fn architecture(&self) -> Architecture {
        return Architecture::from_value(self.inner.lock().unwrap().architecture() as u16);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dotnet_metadata_token_virtual_addresses(&self) -> BTreeMap<u64, u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_metadata_token_virtual_addresses()
    }

    #[pyo3(text_signature = "($self, metadata_token)")]
    pub fn dotnet_metadata_token_to_virtual_address(&self, metadata_token: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_metadata_token_to_virtual_address(metadata_token)
    }

    #[pyo3(text_signature = "($self, metadata_token)")]
    pub fn dotnet_metadata_token_to_relative_virtual_address(
        &self,
        metadata_token: u64,
    ) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_metadata_token_to_relative_virtual_address(metadata_token)
    }

    #[pyo3(text_signature = "($self, metadata_token)")]
    pub fn dotnet_metadata_token_to_file_offset(&self, metadata_token: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_metadata_token_to_file_offset(metadata_token)
    }

    #[pyo3(text_signature = "($self, virtual_address)")]
    pub fn dotnet_virtual_address_to_metadata_token(&self, virtual_address: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_virtual_address_to_metadata_token(virtual_address)
    }

    #[pyo3(text_signature = "($self, relative_virtual_address)")]
    pub fn dotnet_relative_virtual_address_to_metadata_token(
        &self,
        relative_virtual_address: u64,
    ) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_relative_virtual_address_to_metadata_token(relative_virtual_address)
    }

    #[pyo3(text_signature = "($self, file_offset)")]
    pub fn dotnet_file_offset_to_metadata_token(&self, file_offset: u64) -> Option<u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_file_offset_to_metadata_token(file_offset)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dotnet_executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_executable_virtual_address_ranges()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the executable virtual address ranges for the image.
    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        self.inner
            .lock()
            .unwrap()
            .executable_virtual_address_ranges()
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

    #[pyo3(text_signature = "($self)")]
    pub fn pogo_virtual_addresses(&self) -> HashMap<u64, String> {
        self.inner.lock().unwrap().pogo_virtual_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlscallbacks(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().tlscallback_virtual_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dotnet_entrypoint_virtual_addresses(&self) -> BTreeSet<u64> {
        self.inner
            .lock()
            .unwrap()
            .dotnet_entrypoint_virtual_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entrypoint_virtual_addresses(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().entrypoint_virtual_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the image entrypoint virtual address.
    pub fn entrypoint_virtual_address(&self) -> u64 {
        self.inner.lock().unwrap().entrypoint_virtual_address()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sizeofheaders(&self) -> u64 {
        self.inner.lock().unwrap().sizeofheaders()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return an `Image` view over the PE contents.
    pub fn image(&self, py: Python<'_>) -> PyResult<Py<Image>> {
        let result = self
            .inner
            .lock()
            .unwrap()
            .image()
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        Py::new(py, Image { inner: result })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the imaging pipeline over the mapped PE contents.
    pub fn imaging(&self) -> PyResult<Imaging> {
        let result = self
            .inner
            .lock()
            .unwrap()
            .imaging()
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        Ok(Imaging::from_inner(result))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the total size of the image.
    pub fn size(&self) -> u64 {
        self.inner.lock().unwrap().size()
    }

    #[staticmethod]
    /// Align a section virtual address using PE alignment rules.
    pub fn align_section_virtual_address(
        value: u64,
        section_alignment: u64,
        file_alignment: u64,
    ) -> u64 {
        InnerPe::align_section_virtual_address(value, section_alignment, file_alignment)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn export_virtual_addresses(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().export_virtual_addresses()
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
    /// Return the associated `File` helper for this image.
    pub fn file(&self, py: Python<'_>) -> PyResult<Py<File>> {
        let config = self.inner.lock().unwrap().config.clone();
        let file = self.inner.lock().unwrap().file().clone();
        Py::new(
            py,
            File {
                inner: file,
                config: Py::new(
                    py,
                    Config {
                        inner: Arc::new(Mutex::new(config)),
                    },
                )?,
            },
        )
    }

    #[pyo3(text_signature = "($self)")]
    pub fn imagebase(&self) -> u64 {
        self.inner.lock().unwrap().imagebase()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn section_alignment(&self) -> u64 {
        self.inner.lock().unwrap().section_alignment()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn file_alignment(&self) -> u64 {
        self.inner.lock().unwrap().file_alignment()
    }
}

#[pymodule]
#[pyo3(name = "pe")]
pub fn pe_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PE>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.formats.pe", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.formats.pe")?;
    Ok(())
}
