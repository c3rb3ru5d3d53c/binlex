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
pub(crate) struct HilbertRenderer {
    cell_size: usize,
}

impl Default for HilbertRenderer {
    fn default() -> Self {
        Self { cell_size: 1 }
    }
}

impl HilbertRenderer {
    pub(crate) fn new(cell_size: Option<usize>) -> Self {
        let default = Self::default();
        Self {
            cell_size: cell_size.unwrap_or(default.cell_size),
        }
    }

    pub(crate) fn render(&self, data: &[u8], palette: Palette) -> Render {
        let cell_size = self.cell_size.max(1);
        let side = resolve_side(data.len());
        let total_cells = side * side;
        let total_width = side * cell_size;
        let total_height = side * cell_size;
        let mut grid = vec![(0u8, 0u8, 0u8); total_cells];

        for i in 0..data.len().min(total_cells) {
            let (x, y) = hilbert_xy(side, i);
            grid[(y * side) + x] = palette.map_byte_rgb(data[i]);
        }

        let mut cells = Vec::with_capacity(total_cells);
        for (index, rgb) in grid.into_iter().enumerate() {
            let x = index % side;
            let y = index / side;
            cells.push(RenderCell::new(
                index,
                index as u64,
                x * cell_size,
                y * cell_size,
                cell_size,
                cell_size,
                rgb,
            ));
        }

        Render::from_cells(cells, total_width, total_height, total_cells, side)
    }
}

fn resolve_side(data_len: usize) -> usize {
    let mut side = 1usize;
    while side.saturating_mul(side) < data_len.max(1) {
        side = side.saturating_mul(2);
    }
    side.max(1)
}

fn hilbert_xy(side: usize, index: usize) -> (usize, usize) {
    let mut t = index;
    let mut x = 0usize;
    let mut y = 0usize;
    let mut s = 1usize;

    while s < side {
        let rx = 1 & (t / 2);
        let ry = 1 & (t ^ rx);
        let (nx, ny) = rot(s, x, y, rx, ry);
        x = nx + (s * rx);
        y = ny + (s * ry);
        t /= 4;
        s *= 2;
    }

    (x, y)
}

fn rot(n: usize, x: usize, y: usize, rx: usize, ry: usize) -> (usize, usize) {
    if ry == 0 {
        if rx == 1 {
            return (n - 1 - y, n - 1 - x);
        }
        return (y, x);
    }

    (x, y)
}
