pub mod hexdump;

use crate::utilities::hexdump::hexdump_init;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "utilities")]
pub fn utilities_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(hexdump_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.utilities", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.utilities")?;
    Ok(())
}
