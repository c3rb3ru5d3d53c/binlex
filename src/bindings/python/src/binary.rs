use pyo3::prelude::*;

use binlex::binary::Binary as InnerBinary;

#[pyclass]
pub struct Binary;

#[pymethods]
impl Binary {
    #[staticmethod]
    pub fn entropy(bytes: Vec<u8>) -> Option<f64> {
        InnerBinary::entropy(&bytes)
    }
    #[staticmethod]
    pub fn to_hex(bytes: Vec<u8>) -> String {
        InnerBinary::to_hex(&bytes)
    }
    #[staticmethod]
    pub fn hexdump(bytes: Vec<u8>, address: u64) -> String {
        InnerBinary::hexdump(&bytes, address)
    }
}

#[pymodule]
#[pyo3(name = "binary")]
pub fn binary_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Binary>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.binary", m)?;
    m.setattr("__name__", "binlex.binary")?;
    Ok(())
}
