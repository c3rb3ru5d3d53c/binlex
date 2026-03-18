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

use crate::imaging::palette::Palette;
use binlex::imaging::Render as InnerRender;
use binlex::imaging::RenderCell as InnerRenderCell;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyBytesMethods};
use pyo3::Py;
use std::sync::{Arc, Mutex};

/// Describe a single cell in a rendered binary grid.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct RenderCell {
    inner: InnerRenderCell,
}

#[pymethods]
impl RenderCell {
    #[getter]
    /// Return the zero-based cell index.
    pub fn index(&self) -> usize {
        self.inner.index()
    }

    #[getter]
    /// Return the original byte address represented by this cell.
    pub fn address(&self) -> u64 {
        self.inner.address()
    }

    #[getter]
    /// Return the x coordinate of the cell.
    pub fn x(&self) -> usize {
        self.inner.x()
    }

    #[getter]
    /// Return the y coordinate of the cell.
    pub fn y(&self) -> usize {
        self.inner.y()
    }

    #[getter]
    /// Return the cell width in pixels.
    pub fn width(&self) -> usize {
        self.inner.width()
    }

    #[getter]
    /// Return the cell height in pixels.
    pub fn height(&self) -> usize {
        self.inner.height()
    }

    #[getter]
    /// Return the RGB tuple assigned to the cell.
    pub fn rgb(&self) -> (u8, u8, u8) {
        self.inner.rgb()
    }
}

/// Render bytes into an in-memory grid of colored cells.
#[pyclass]
pub struct Render {
    inner: Arc<Mutex<InnerRender>>,
}

#[pymethods]
impl Render {
    #[new]
    #[pyo3(signature = (data, palette, cell_size=1, fixed_width=16))]
    #[pyo3(text_signature = "(data, palette, cell_size=1, fixed_width=16)")]
    /// Create a render object for the provided bytes and palette.
    pub fn new(
        py: Python,
        data: Py<PyBytes>,
        palette: Py<Palette>,
        cell_size: usize,
        fixed_width: usize,
    ) -> Self {
        let inner_data = data.bind(py).as_bytes();
        let inner_palette = palette.borrow(py).inner.lock().unwrap().clone();
        Self {
            inner: Arc::new(Mutex::new(InnerRender::new_with_options(
                inner_data,
                inner_palette,
                cell_size,
                fixed_width,
            ))),
        }
    }

    #[getter]
    /// Return the total rendered width in pixels.
    pub fn total_width(&self) -> usize {
        self.inner.lock().unwrap().total_width()
    }

    #[getter]
    /// Return the total rendered height in pixels.
    pub fn total_height(&self) -> usize {
        self.inner.lock().unwrap().total_height()
    }

    #[getter]
    /// Return the total number of rendered cells.
    pub fn total_cells(&self) -> usize {
        self.inner.lock().unwrap().total_cells()
    }

    #[getter]
    /// Return the fixed row width used for rendering.
    pub fn fixed_width(&self) -> usize {
        self.inner.lock().unwrap().fixed_width()
    }

    #[getter]
    /// Return all rendered cells in row-major order.
    pub fn cells(&self) -> Vec<RenderCell> {
        self.inner
            .lock()
            .unwrap()
            .cells()
            .iter()
            .cloned()
            .map(|inner| RenderCell { inner })
            .collect()
    }
}

#[pymodule]
#[pyo3(name = "render")]
pub fn render_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Render>()?;
    m.add_class::<RenderCell>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.imaging.render", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.imaging.render")?;
    Ok(())
}
