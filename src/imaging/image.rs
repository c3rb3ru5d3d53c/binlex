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

use crate::imaging::Palette;

pub(crate) struct Cell {
    pub(crate) index: usize,
    pub(crate) address: u64,
    pub(crate) rgb: (u8, u8, u8),
}

pub(crate) struct Image {
    pub(crate) cells: Vec<Cell>,
    pub(crate) total_cells: usize,
    pub(crate) cell_size: usize,
    pub(crate) fixed_width: usize,
}

impl Image {
    pub(crate) fn new(data: &[u8], palette: Palette, cell_size: usize, fixed_width: usize) -> Self {
        let fixed_width = fixed_width.max(1);
        let mut cells = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            cells.push(Cell {
                index: i,
                address: i as u64,
                rgb: palette.map_byte_rgb(byte),
            });
        }

        Self {
            cells,
            total_cells: data.len(),
            cell_size,
            fixed_width,
        }
    }

    pub(crate) fn total_height(&self) -> usize {
        self.total_cells.div_ceil(self.fixed_width) * self.cell_size
    }
}
