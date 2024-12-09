use pyo3::prelude::*;
use std::io::Error;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use pyo3::types::PyType;
use binlex::formats::MACHO as InnerMACHO;
use crate::Architecture;
use crate::types::memorymappedfile::MemoryMappedFile;
use crate::Config;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass(unsendable)]
pub struct MACHO {
    pub inner: Arc<Mutex<InnerMACHO>>,
}

#[pymethods]
impl MACHO {
    #[new]
    #[pyo3(text_signature = "(path, config)")]
    pub fn new(py: Python, path: String, config: Py<Config>) -> Result<Self, Error> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerMACHO::new(path, inner_config)?;
        Ok(Self{
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[classmethod]
    #[pyo3(text_signature = "(bytes, config)")]
    pub fn from_bytes(_: &Bound<'_, PyType>, py: Python, bytes: Vec<u8>, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerMACHO::from_bytes(bytes, inner_config)?;
        Ok(Self { inner: Arc::new(Mutex::new(inner)) })
    }

    #[pyo3(text_signature = "($self, relative_virtual_address, slice)")]
    pub fn relative_virtual_address_to_virtual_address(&self, relative_virtual_address: u64, slice: usize) -> Option<u64> {
        self.inner.lock().unwrap().relative_virtual_address_to_virtual_address(relative_virtual_address, slice)
    }

    #[pyo3(text_signature = "($self, file_offset, slice)")]
    pub fn file_offset_to_virtual_address(&self, file_offset: u64, slice: usize) -> Option<u64> {
        self.inner.lock().unwrap().file_offset_to_virtual_address(file_offset, slice)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_slices(&self) -> usize {
        self.inner.lock().unwrap().number_of_slices()
    }

    #[pyo3(text_signature = "($self, slice)")]
    pub fn entrypoint(&self, slice: usize) -> Option<u64> {
        self.inner.lock().unwrap().entrypoint(slice)
    }

    #[pyo3(text_signature = "($self, slice)")]
    pub fn imagebase(&self, slice: usize) -> Option<u64> {
        self.inner.lock().unwrap().imagebase(slice)
    }

    #[pyo3(text_signature = "($self, slice)")]
    pub fn sizeofheaders(&self, slice: usize) -> Option<u64> {
        self.inner.lock().unwrap().sizeofheaders(slice)
    }

    #[pyo3(text_signature = "($self, slice)")]
    pub fn architecture(&self, slice: usize) -> Option<Architecture> {
        let architecture = self.inner.lock().unwrap().architecture(slice);
        if architecture.is_none() { return None; }
        Some(Architecture{inner: architecture.unwrap()})
    }

    #[pyo3(text_signature = "($self, slice)")]
    pub fn entrypoints(&self, slice: usize) -> BTreeSet<u64> {
        self.inner.lock().unwrap().entrypoints(slice)
    }

    #[pyo3(text_signature = "($self, slice)")]
    pub fn exports(&self, slice: usize) -> BTreeSet<u64> {
        self.inner.lock().unwrap().exports(slice)
    }

    #[pyo3(text_signature = "($self, slice)")]
    pub fn executable_virtual_address_ranges(&self, slice: usize) -> BTreeMap<u64, u64> {
        self.inner.lock().unwrap().executable_virtual_address_ranges(slice)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn image(&self, py: Python<'_>, slice: usize) -> PyResult<Py<MemoryMappedFile>> {
        let result = self.inner.lock().unwrap().image(slice).map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(e.to_string())
        })?;
        let py_memory_mapped_file = Py::new(py, MemoryMappedFile { inner: result, mmap: None})?;
        Ok(py_memory_mapped_file)
    }
}

#[pymodule]
#[pyo3(name = "macho")]
pub fn macho_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MACHO>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.formats.macho", m)?;
    m.setattr("__name__", "binlex.formats.macho")?;
    Ok(())
}
