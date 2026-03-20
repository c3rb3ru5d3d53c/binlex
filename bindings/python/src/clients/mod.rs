pub mod milvus;
pub mod minio;
pub mod server;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "clients")]
pub fn clients_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(milvus::milvus_init))?;
    m.add_wrapped(wrap_pymodule!(minio::minio_init))?;
    m.add_wrapped(wrap_pymodule!(server::server_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.clients", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.clients")?;
    Ok(())
}
