pub mod chromosome;
pub mod gene;
pub mod allelepair;

pub use crate::genetics::chromosome::chromosome_init;
pub use crate::genetics::chromosome::Chromosome;
pub use crate::genetics::chromosome::ChromosomeSimilarity;

pub use crate::genetics::allelepair::allelepair_init;
pub use crate::genetics::allelepair::AllelePair;

pub use crate::genetics::gene::gene_init;
pub use crate::genetics::gene::Gene;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "genetics")]
pub fn genitics_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(gene_init))?;
    m.add_class::<Gene>()?;
    m.add_wrapped(wrap_pymodule!(allelepair_init))?;
    m.add_class::<AllelePair>()?;
    m.add_wrapped(wrap_pymodule!(chromosome_init))?;
    m.add_class::<Chromosome>()?;
    m.add_class::<ChromosomeSimilarity>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.genetics", m)?;
    m.setattr("__name__", "binlex.genetics")?;
    Ok(())
}
