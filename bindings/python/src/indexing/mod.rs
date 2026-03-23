pub mod lancedb;
pub mod milvus;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "indexing")]
pub fn indexing_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(milvus::milvus_init))?;
    m.add_wrapped(wrap_pymodule!(lancedb::lancedb_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.indexing", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.indexing")?;
    Ok(())
}
