use pyo3::prelude::*;
use binlex::types::LZ4String as InnerLZ4String;

#[pyclass]
pub struct LZ4String {
    pub inner: InnerLZ4String,
}

#[pymethods]
impl LZ4String {
    #[new]
    pub fn new(string: String) -> Self {
        Self {
            inner: InnerLZ4String::new(&string)
        }
    }

    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.inner))
    }

}

#[pymodule]
#[pyo3(name = "lz4string")]
pub fn memorymappedfile_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LZ4String>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.types.lz4string", m)?;
    m.setattr("__name__", "binlex.types.lz4string")?;
    Ok(())
}
