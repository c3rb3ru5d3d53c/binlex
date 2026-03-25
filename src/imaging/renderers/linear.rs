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

#[derive(Clone)]
pub(crate) struct LinearRenderer {
    cell_size: usize,
    fixed_width: usize,
}

impl Default for LinearRenderer {
    fn default() -> Self {
        Self {
            cell_size: 1,
            fixed_width: 16,
        }
    }
}

impl LinearRenderer {
    pub(crate) fn new(cell_size: Option<usize>, fixed_width: Option<usize>) -> Self {
        let default = Self::default();
        Self {
            cell_size: cell_size.unwrap_or(default.cell_size),
            fixed_width: fixed_width.unwrap_or(default.fixed_width),
        }
    }

    pub(crate) fn render(&self, data: &[u8], palette: Palette) -> Render {
        let fixed_width = self.fixed_width.max(1);
        let total_cells = data.len();
        let total_width = fixed_width * self.cell_size;
        let total_height = total_cells.div_ceil(fixed_width) * self.cell_size;
        let mut cells = Vec::with_capacity(total_cells);

        for (i, &byte) in data.iter().enumerate() {
            let row = i / fixed_width;
            let col = i % fixed_width;

            cells.push(RenderCell::new(
                i,
                i as u64,
                col * self.cell_size,
                row * self.cell_size,
                self.cell_size,
                self.cell_size,
                palette.map_byte_rgb(byte),
            ));
        }

        Render::from_cells(cells, total_width, total_height, total_cells, fixed_width)
    }
}
