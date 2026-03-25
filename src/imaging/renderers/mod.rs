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

pub(crate) mod bitmap;
pub(crate) mod digraph;
pub(crate) mod entropy;
pub(crate) mod hilbert;
pub(crate) mod linear;

use crate::imaging::palette::Palette;
use crate::imaging::render::Render;
pub(crate) use bitmap::BitmapRenderer;
pub(crate) use digraph::DigraphRenderer;
pub(crate) use entropy::EntropyRenderer;
pub(crate) use hilbert::HilbertRenderer;
pub(crate) use linear::LinearRenderer;

#[derive(Clone)]
pub(crate) enum Renderer {
    Bitmap(BitmapRenderer),
    Digraph(DigraphRenderer),
    Entropy(EntropyRenderer),
    Hilbert(HilbertRenderer),
    Linear(LinearRenderer),
}

impl Default for Renderer {
    fn default() -> Self {
        Self::Linear(LinearRenderer::default())
    }
}

impl Renderer {
    pub(crate) fn bitmap(cell_size: Option<usize>, fixed_width: Option<usize>) -> Self {
        Self::Bitmap(BitmapRenderer::new(cell_size, fixed_width))
    }

    pub(crate) fn digraph(
        cell_size: Option<usize>,
        axis_size: Option<usize>,
        stride: Option<usize>,
        offset: Option<usize>,
        window_size: Option<usize>,
        intensity: Option<String>,
    ) -> Self {
        Self::Digraph(DigraphRenderer::new(
            cell_size,
            axis_size,
            stride,
            offset,
            window_size,
            intensity,
        ))
    }

    pub(crate) fn entropy(
        window_size: Option<usize>,
        cell_size: Option<usize>,
        fixed_width: Option<usize>,
    ) -> Self {
        Self::Entropy(EntropyRenderer::new(window_size, cell_size, fixed_width))
    }

    pub(crate) fn hilbert(cell_size: Option<usize>) -> Self {
        Self::Hilbert(HilbertRenderer::new(cell_size))
    }

    pub(crate) fn linear(cell_size: Option<usize>, fixed_width: Option<usize>) -> Self {
        Self::Linear(LinearRenderer::new(cell_size, fixed_width))
    }

    pub(crate) fn render(&self, data: &[u8], palette: Palette) -> Render {
        match self {
            Self::Bitmap(renderer) => renderer.render(data, palette),
            Self::Digraph(renderer) => renderer.render(data, palette),
            Self::Entropy(renderer) => renderer.render(data, palette),
            Self::Hilbert(renderer) => renderer.render(data, palette),
            Self::Linear(renderer) => renderer.render(data, palette),
        }
    }
}
