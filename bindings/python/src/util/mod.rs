pub mod hexdump;

use crate::util::hexdump::hexdump_init;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "util")]
pub fn util_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(hexdump_init))?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.util", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.util")?;
    Ok(())
}
