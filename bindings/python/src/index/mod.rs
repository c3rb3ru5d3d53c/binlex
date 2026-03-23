pub mod local;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "index")]
pub fn index_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(local::local_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.index", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.index")?;
    Ok(())
}
