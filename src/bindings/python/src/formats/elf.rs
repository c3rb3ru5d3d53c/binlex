use pyo3::prelude::*;
use std::io::Error;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use binlex::formats::ELF as InnerELF;
use crate::Architecture;
use crate::types::memorymappedfile::MemoryMappedFile;
use pyo3::types::PyType;
use crate::Config;
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
        Ok(Self{
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[classmethod]
    #[pyo3(text_signature = "(bytes, config)")]
    pub fn from_bytes(_: &Bound<'_, PyType>, py: Python, bytes: Vec<u8>, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerELF::from_bytes(bytes, inner_config)?;
        Ok(Self { inner: Arc::new(Mutex::new(inner)) })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn architecture(&self) -> Architecture {
        return Architecture::new(self.inner.lock().unwrap().architecture() as u16);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        self.inner.lock().unwrap().executable_virtual_address_ranges()
    }

    #[pyo3(text_signature = "($self, relative_virtual_address)")]
    pub fn relative_virtual_address_to_virtual_address(&self, relative_virtual_address: u64) -> u64 {
        self.inner.lock().unwrap().relative_virtual_address_to_virtual_address(relative_virtual_address)
    }

    #[pyo3(text_signature = "($self, file_offset)")]
    pub fn file_offset_to_virtual_address(&self, file_offset: u64) -> Option<u64> {
        self.inner.lock().unwrap().file_offset_to_virtual_address(file_offset)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entrypoints(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().entrypoints()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entrypoint(&self) -> u64  {
        self.inner.lock().unwrap().entrypoint()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn image(&self, py: Python<'_>) -> PyResult<Py<MemoryMappedFile>> {
        let result = self.inner.lock().unwrap().image().map_err(|e| {
            pyo3::exceptions::PyIOError::new_err(e.to_string())
        })?;
        let py_memory_mapped_file = Py::new(py, MemoryMappedFile { inner: result, mmap: None})?;
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
    pub fn exports(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().exports()
    }

}

#[pymodule]
#[pyo3(name = "elf")]
pub fn elf_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ELF>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.formats.elf", m)?;
    m.setattr("__name__", "binlex.formats.elf")?;
    Ok(())
}
