pub mod formats;
pub mod types;
pub mod config;
pub mod hashing;
pub mod binary;
pub mod disassemblers;
pub mod controlflow;

pub use config::Architecture;
pub use binary::Binary;
pub use config::Config;

use crate::formats::formats_init;
use crate::types::types_init;
use crate::config::config_init;
use crate::binary::binary_init;
use crate::disassemblers::disassemblers_init;
use crate::controlflow::controlflow_init;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
fn binlex(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(formats_init))?;
    m.add_wrapped(wrap_pymodule!(controlflow_init))?;
    m.add_wrapped(wrap_pymodule!(types_init))?;
    m.add_wrapped(wrap_pymodule!(config_init))?;
    m.add_wrapped(wrap_pymodule!(binary_init))?;
    m.add_wrapped(wrap_pymodule!(disassemblers_init))?;
    m.add_class::<Binary>()?;
    m.add_class::<Config>()?;
    Ok(())
}
