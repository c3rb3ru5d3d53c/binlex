pub mod disassembler;

use pyo3::{prelude::*, wrap_pymodule};

use disassembler::binlex_cil_disassembler_init;
use disassembler::Disassembler;

#[pymodule]
#[pyo3(name = "cil")]
pub fn cil_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(binlex_cil_disassembler_init))?;
    m.add_class::<Disassembler>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.disassemblers.custom.cil", m)?;
    m.setattr("__name__", "binlex.disassemblers.custom.cil")?;
    Ok(())
}
