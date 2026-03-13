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

#[derive(Clone)]
pub struct RenderCell {
    index: usize,
    address: u64,
    x: usize,
    y: usize,
    width: usize,
    height: usize,
    rgb: (u8, u8, u8),
}

impl RenderCell {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn x(&self) -> usize {
        self.x
    }

    pub fn y(&self) -> usize {
        self.y
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn rgb(&self) -> (u8, u8, u8) {
        self.rgb
    }
}

#[derive(Clone)]
pub struct Render {
    cells: Vec<RenderCell>,
    total_width: usize,
    total_height: usize,
    total_cells: usize,
    fixed_width: usize,
}

impl Render {
    pub fn new(data: &[u8], palette: Palette) -> Self {
        Self::new_with_options(data, palette, 1, 16)
    }

    pub fn new_with_options(
        data: &[u8],
        palette: Palette,
        cell_size: usize,
        fixed_width: usize,
    ) -> Self {
        let fixed_width = fixed_width.max(1);
        let total_cells = data.len();
        let total_width = fixed_width * cell_size;
        let total_height = total_cells.div_ceil(fixed_width) * cell_size;
        let mut cells = Vec::with_capacity(total_cells);

        for (i, &byte) in data.iter().enumerate() {
            let row = i / fixed_width;
            let col = i % fixed_width;

            cells.push(RenderCell {
                index: i,
                address: i as u64,
                x: col * cell_size,
                y: row * cell_size,
                width: cell_size,
                height: cell_size,
                rgb: palette.map_byte_rgb(byte),
            });
        }

        Self {
            cells,
            total_width,
            total_height,
            total_cells,
            fixed_width,
        }
    }

    pub fn cells(&self) -> &[RenderCell] {
        &self.cells
    }

    pub fn total_width(&self) -> usize {
        self.total_width
    }

    pub fn total_height(&self) -> usize {
        self.total_height
    }

    pub fn total_cells(&self) -> usize {
        self.total_cells
    }

    pub fn fixed_width(&self) -> usize {
        self.fixed_width
    }
}
