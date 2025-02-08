
pub mod disassembler;

use pyo3::{prelude::*, wrap_pymodule};

use crate::disassemblers::capstone::x86::disassembler::disassembler_init;
use crate::disassemblers::capstone::x86::disassembler::Disassembler;

#[pymodule]
#[pyo3(name = "capstone_x86")]
pub fn capstone_x86_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(disassembler_init))?;
    m.add_class::<Disassembler>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.disassemblers.capstone.x86", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.disassemblers.capstone.x86")?;
    Ok(())
}
