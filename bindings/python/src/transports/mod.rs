pub mod http;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "transports")]
pub fn transports_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(http::http_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.transports", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.transports")?;
    Ok(())
}
