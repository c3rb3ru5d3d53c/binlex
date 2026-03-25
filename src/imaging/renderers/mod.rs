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

pub(crate) mod linear;

use crate::imaging::palette::Palette;
use crate::imaging::render::Render;
pub(crate) use linear::LinearRenderer;

#[derive(Clone)]
pub(crate) enum Renderer {
    Linear(LinearRenderer),
}

impl Default for Renderer {
    fn default() -> Self {
        Self::Linear(LinearRenderer::default())
    }
}

impl Renderer {
    pub(crate) fn linear(cell_size: Option<usize>, fixed_width: Option<usize>) -> Self {
        Self::Linear(LinearRenderer::new(cell_size, fixed_width))
    }

    pub(crate) fn render(&self, data: &[u8], palette: Palette) -> Render {
        match self {
            Self::Linear(renderer) => renderer.render(data, palette),
        }
    }
}
