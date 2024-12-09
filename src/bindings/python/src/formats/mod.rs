pub mod file;
pub mod pe;
pub mod elf;
pub mod macho;

use crate::formats::file::file_init;
use crate::formats::pe::pe_init;
use crate::formats::macho::macho_init;

pub use crate::formats::pe::PE;
pub use crate::formats::file::File;
pub use crate::formats::elf::ELF;
pub use crate::formats::macho::MACHO;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "formats")]
pub fn formats_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(file_init))?;
    m.add_wrapped(wrap_pymodule!(pe_init))?;
    m.add_wrapped(wrap_pymodule!(macho_init))?;
    m.add_class::<PE>()?;
    m.add_class::<File>()?;
    m.add_class::<ELF>()?;
    m.add_class::<MACHO>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.formats", m)?;
    m.setattr("__name__", "binlex.formats")?;
    Ok(())
}
