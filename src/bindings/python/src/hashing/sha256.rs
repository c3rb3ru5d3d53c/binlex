use pyo3::prelude::*;

use binlex::hashing::sha256::SHA256 as InnerSHA256;

#[pyclass]
pub struct SHA256 {
    pub bytes: Vec<u8>
}

#[pymethods]
impl SHA256 {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: bytes,
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn hexdigest(&self) -> Option<String> {
        InnerSHA256::new(&self.bytes).hexdigest()
    }

}

#[pymodule]
#[pyo3(name = "sha256")]
pub fn sha256_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SHA256>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.hashing.sha256", m)?;
    m.setattr("__name__", "binlex.hashing.sha256")?;
    Ok(())
}
