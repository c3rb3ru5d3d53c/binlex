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

use crate::config::Config;
use crate::imaging::{Terminal, PNG, SVG};
use binlex::imaging::{
    Imaging as InnerImaging, ImagingNormalized as InnerImagingNormalized,
    ImagingPalette as InnerImagingPalette, ImagingRenderer as InnerImagingRenderer,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyBytesMethods};
use pyo3::Py;
use std::sync::{Arc, Mutex};

#[pyclass]
pub struct Imaging {
    pub(crate) inner: Arc<Mutex<InnerImaging>>,
}

impl Imaging {
    pub(crate) fn from_inner(inner: InnerImaging) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl Imaging {
    #[new]
    #[pyo3(text_signature = "(data, config)")]
    /// Create an imaging pipeline for the provided bytes.
    pub fn new(py: Python, data: Py<PyBytes>, config: Py<Config>) -> Self {
        let inner_data = data.bind(py).as_bytes().to_vec();
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        Self::from_inner(InnerImaging::new(inner_data, inner_config))
    }

    #[pyo3(signature = (cell_size=None, fixed_width=None))]
    #[pyo3(text_signature = "($self, cell_size=None, fixed_width=None)")]
    pub fn linear(&self, cell_size: Option<usize>, fixed_width: Option<usize>) -> ImagingRenderer {
        ImagingRenderer::from_inner(
            self.inner
                .lock()
                .unwrap()
                .clone()
                .linear(cell_size, fixed_width),
        )
    }

    #[pyo3(signature = (cell_size=None, fixed_width=None))]
    #[pyo3(text_signature = "($self, cell_size=None, fixed_width=None)")]
    pub fn bitmap(&self, cell_size: Option<usize>, fixed_width: Option<usize>) -> ImagingRenderer {
        ImagingRenderer::from_inner(
            self.inner
                .lock()
                .unwrap()
                .clone()
                .bitmap(cell_size, fixed_width),
        )
    }

    #[pyo3(signature = (cell_size=None, axis_size=None, stride=None, offset=None, window_size=None, intensity=None))]
    #[pyo3(
        text_signature = "($self, cell_size=None, axis_size=None, stride=None, offset=None, window_size=None, intensity=None)"
    )]
    pub fn digraph(
        &self,
        cell_size: Option<usize>,
        axis_size: Option<usize>,
        stride: Option<usize>,
        offset: Option<usize>,
        window_size: Option<usize>,
        intensity: Option<String>,
    ) -> ImagingRenderer {
        ImagingRenderer::from_inner(self.inner.lock().unwrap().clone().digraph(
            cell_size,
            axis_size,
            stride,
            offset,
            window_size,
            intensity,
        ))
    }

    #[pyo3(signature = (window_size=None, cell_size=None, fixed_width=None))]
    #[pyo3(text_signature = "($self, window_size=None, cell_size=None, fixed_width=None)")]
    pub fn entropy(
        &self,
        window_size: Option<usize>,
        cell_size: Option<usize>,
        fixed_width: Option<usize>,
    ) -> ImagingRenderer {
        ImagingRenderer::from_inner(self.inner.lock().unwrap().clone().entropy(
            window_size,
            cell_size,
            fixed_width,
        ))
    }

    #[pyo3(signature = (cell_size=None))]
    #[pyo3(text_signature = "($self, cell_size=None)")]
    pub fn hilbert(&self, cell_size: Option<usize>) -> ImagingRenderer {
        ImagingRenderer::from_inner(self.inner.lock().unwrap().clone().hilbert(cell_size))
    }
}

#[pyclass]
pub struct ImagingRenderer {
    pub(crate) inner: Arc<Mutex<InnerImagingRenderer>>,
}

impl ImagingRenderer {
    pub(crate) fn from_inner(inner: InnerImagingRenderer) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl ImagingRenderer {
    #[pyo3(text_signature = "($self)")]
    pub fn grayscale(&self) -> ImagingPalette {
        ImagingPalette::from_inner(self.inner.lock().unwrap().clone().grayscale())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn heatmap(&self) -> ImagingPalette {
        ImagingPalette::from_inner(self.inner.lock().unwrap().clone().heatmap())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bluegreen(&self) -> ImagingPalette {
        ImagingPalette::from_inner(self.inner.lock().unwrap().clone().bluegreen())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn redblack(&self) -> ImagingPalette {
        ImagingPalette::from_inner(self.inner.lock().unwrap().clone().redblack())
    }
}

#[pyclass]
pub struct ImagingPalette {
    pub(crate) inner: Arc<Mutex<InnerImagingPalette>>,
}

impl ImagingPalette {
    pub(crate) fn from_inner(inner: InnerImagingPalette) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl ImagingPalette {
    #[pyo3(text_signature = "($self, width, height)")]
    pub fn fit(&self, width: usize, height: usize) -> ImagingNormalized {
        ImagingNormalized::from_inner(self.inner.lock().unwrap().fit(width, height))
    }

    #[pyo3(text_signature = "($self, width, height)")]
    pub fn fill(&self, width: usize, height: usize) -> ImagingNormalized {
        ImagingNormalized::from_inner(self.inner.lock().unwrap().fill(width, height))
    }

    #[pyo3(text_signature = "($self, width, height)")]
    pub fn exact(&self, width: usize, height: usize) -> ImagingNormalized {
        ImagingNormalized::from_inner(self.inner.lock().unwrap().exact(width, height))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn png(&self) -> PNG {
        PNG::from_inner(self.inner.lock().unwrap().png())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn svg(&self) -> SVG {
        SVG::from_inner(self.inner.lock().unwrap().svg())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn terminal(&self) -> Terminal {
        Terminal::from_inner(self.inner.lock().unwrap().terminal())
    }
}

#[pyclass]
pub struct ImagingNormalized {
    pub(crate) inner: Arc<Mutex<InnerImagingNormalized>>,
}

impl ImagingNormalized {
    pub(crate) fn from_inner(inner: InnerImagingNormalized) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl ImagingNormalized {
    #[pyo3(text_signature = "($self)")]
    pub fn png(&self) -> PNG {
        PNG::from_inner(self.inner.lock().unwrap().png())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn svg(&self) -> SVG {
        SVG::from_inner(self.inner.lock().unwrap().svg())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn terminal(&self) -> Terminal {
        Terminal::from_inner(self.inner.lock().unwrap().terminal())
    }
}

#[pymodule]
#[pyo3(name = "pipeline")]
pub fn pipeline_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Imaging>()?;
    m.add_class::<ImagingRenderer>()?;
    m.add_class::<ImagingPalette>()?;
    m.add_class::<ImagingNormalized>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.imaging.pipeline", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.imaging.pipeline")?;
    Ok(())
}
