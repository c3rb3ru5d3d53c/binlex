pub mod minio;
pub mod object_store;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "storage")]
pub fn storage_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(minio::minio_init))?;
    m.add_wrapped(wrap_pymodule!(object_store::object_store_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.storage", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.storage")?;
    Ok(())
}
