use pyo3::prelude::*;

pub mod entropy;
pub mod similarity;
pub mod stats;

pub use entropy::entropy_init;

#[pymodule]
#[pyo3(name = "math")]
pub fn math_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    similarity::register(py, m)?;
    stats::register(m)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.math", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.math")?;
    Ok(())
}
