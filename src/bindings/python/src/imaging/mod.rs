pub mod colormap;

pub use colormap::ColorMap;
pub use colormap::ColorMapType;
use crate::imaging::colormap::colormap_init;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "imaging")]
pub fn imaging_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(colormap_init))?;
    m.add_class::<ColorMap>()?;
    m.add_class::<ColorMapType>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.imaging", m)?;
    m.setattr("__name__", "binlex.imaging")?;
    Ok(())
}
