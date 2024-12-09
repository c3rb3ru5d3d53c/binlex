use pyo3::prelude::*;

use binlex::hashing::tlsh::TLSH as InnerTLSH;

#[pyclass]
pub struct TLSH {
    bytes: Vec<u8>,
}

#[pymethods]
impl TLSH {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes,
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn hexdigest(&self, mininum_byte_size: usize) -> Option<String> {
        InnerTLSH::new(&self.bytes, mininum_byte_size).hexdigest()
    }

}


#[pymodule]
#[pyo3(name = "tlsh")]
pub fn tlsh_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TLSH>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.hashing.tlsh", m)?;
    m.setattr("__name__", "binlex.hashing.tlsh")?;
    Ok(())
}
