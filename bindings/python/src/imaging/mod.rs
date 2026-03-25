// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Python bindings for binary rendering helpers and palette types.

pub mod palette;
pub mod pipeline;
pub mod png;
pub mod render;
pub mod svg;
pub mod terminal;

use crate::imaging::palette::palette_init;
use crate::imaging::pipeline::pipeline_init;
use crate::imaging::png::png_init;
use crate::imaging::render::render_init;
use crate::imaging::svg::svg_init;
use crate::imaging::terminal::terminal_init;
pub use palette::Palette;
pub use pipeline::{Imaging, ImagingPalette, ImagingRenderer};
pub use png::PNG;
pub use render::{Render, RenderCell};
pub use svg::SVG;
pub use terminal::Terminal;

use pyo3::{prelude::*, wrap_pymodule};

#[pymodule]
#[pyo3(name = "imaging")]
pub fn imaging_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(palette_init))?;
    m.add_wrapped(wrap_pymodule!(pipeline_init))?;
    m.add_wrapped(wrap_pymodule!(png_init))?;
    m.add_wrapped(wrap_pymodule!(render_init))?;
    m.add_wrapped(wrap_pymodule!(svg_init))?;
    m.add_wrapped(wrap_pymodule!(terminal_init))?;
    m.add_class::<PNG>()?;
    m.add_class::<Imaging>()?;
    m.add_class::<ImagingRenderer>()?;
    m.add_class::<ImagingPalette>()?;
    m.add_class::<Render>()?;
    m.add_class::<RenderCell>()?;
    m.add_class::<SVG>()?;
    m.add_class::<Terminal>()?;
    m.add_class::<Palette>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.imaging", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.imaging")?;
    Ok(())
}
