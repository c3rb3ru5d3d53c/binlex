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
use crate::imaging::render::{Render, RenderCell};
use crate::math::entropy;

#[derive(Clone)]
pub(crate) struct EntropyRenderer {
    window_size: usize,
    cell_size: usize,
    fixed_width: usize,
}

impl Default for EntropyRenderer {
    fn default() -> Self {
        Self {
            window_size: 64,
            cell_size: 1,
            fixed_width: 64,
        }
    }
}

impl EntropyRenderer {
    pub(crate) fn new(
        window_size: Option<usize>,
        cell_size: Option<usize>,
        fixed_width: Option<usize>,
    ) -> Self {
        let default = Self::default();
        Self {
            window_size: window_size.unwrap_or(default.window_size),
            cell_size: cell_size.unwrap_or(default.cell_size),
            fixed_width: fixed_width.unwrap_or(default.fixed_width),
        }
    }

    pub(crate) fn render(&self, data: &[u8], palette: Palette) -> Render {
        let cell_size = self.cell_size.max(1);
        let window_size = self.window_size.max(1);
        let window_count = data.len().div_ceil(window_size).max(1);
        let fixed_width = self.fixed_width.max(1).min(window_count.max(1));
        let total_cells = fixed_width * window_count.div_ceil(fixed_width);
        let total_width = fixed_width * cell_size;
        let total_height = total_cells.div_ceil(fixed_width) * cell_size;
        let mut cells = Vec::with_capacity(total_cells);

        for i in 0..total_cells {
            let row = i / fixed_width;
            let col = i % fixed_width;
            let rgb = if i < window_count {
                let start = i * window_size;
                let end = (start + window_size).min(data.len());
                let value = entropy::shannon(&data[start..end]).unwrap_or(0.0);
                palette.map_byte_rgb(normalize_entropy(value))
            } else {
                palette.map_byte_rgb(0)
            };

            cells.push(RenderCell::new(
                i,
                (i * window_size) as u64,
                col * cell_size,
                row * cell_size,
                cell_size,
                cell_size,
                rgb,
            ));
        }

        Render::from_cells(cells, total_width, total_height, total_cells, fixed_width)
    }
}

fn normalize_entropy(value: f64) -> u8 {
    (((value.clamp(0.0, 8.0) / 8.0) * 255.0).round() as usize).min(255) as u8
}
