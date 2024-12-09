pub mod cil;

use cil::cil_init;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "custom_disassemblers")]
pub fn custom_disassemblers_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(cil_init))?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.disassemblers.custom", m)?;
    m.setattr("__name__", "binlex.disassemblers.custom")?;
    Ok(())
}
