use pyo3::prelude::*;

use std::io::Error;
use binlex::formats::file::File as InnerFile;
use crate::Config;

#[pyclass]
pub struct File {
    pub inner: InnerFile,
    pub config: Py<Config>,
}

#[pymethods]
impl File {
    #[new]
    #[pyo3(text_signature = "(path, config)")]
    pub fn new(py: Python, path: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerFile::new(path, inner_config)?;
        Ok(Self {
            inner: inner,
            config: config,
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh(&self) -> Option<String> {
        self.inner.tlsh()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sha256(&self) -> Option<String> {
        self.inner.sha256()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn size(&self) -> u64 {
        self.inner.size()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn read(&mut self) -> Result<(), Error> {
        self.inner.read()
    }

}

#[pymodule]
#[pyo3(name = "file")]
pub fn file_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<File>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.formats.file", m)?;
    m.setattr("__name__", "binlex.formats.file")?;
    Ok(())
}
