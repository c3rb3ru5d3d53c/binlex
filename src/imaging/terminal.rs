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
use crate::imaging::image::Image;
use std::io::{self, Write};

pub struct Terminal {
    image: Image,
}

impl Terminal {
    pub fn new(data: &[u8], palette: Palette) -> Self {
        Self::new_with_options(data, palette, 1, 16)
    }

    pub fn new_with_options(
        data: &[u8],
        palette: Palette,
        cell_size: usize,
        fixed_width: usize,
    ) -> Self {
        Self {
            image: Image::new(data, palette, cell_size, fixed_width),
        }
    }

    pub fn print(&self) -> io::Result<()> {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        self.write(&mut stdout)
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if self.image.total_cells == 0 {
            write!(writer, "\x1b[0m")?;
            return Ok(());
        }

        let row_count = self.image.total_cells.div_ceil(self.image.fixed_width);

        for row in 0..row_count {
            let start = row * self.image.fixed_width;
            let end = (start + self.image.fixed_width).min(self.image.total_cells);

            for cell in &self.image.cells[start..end] {
                let (r, g, b) = cell.rgb;
                write!(writer, "\x1b[48;5;{}m  ", Self::rgb_to_ansi256(r, g, b))?;
            }

            writeln!(writer, "\x1b[0m")?;
        }

        write!(writer, "\x1b[0m")?;
        writer.flush()
    }

    pub fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
        if r == g && g == b {
            if r < 8 {
                return 16;
            }
            if r > 248 {
                return 231;
            }
            return 232 + (((r as u16 - 8) * 24) / 247) as u8;
        }

        let red = ((r as f32 / 255.0) * 5.0).round() as u8;
        let green = ((g as f32 / 255.0) * 5.0).round() as u8;
        let blue = ((b as f32 / 255.0) * 5.0).round() as u8;
        16 + (36 * red) + (6 * green) + blue
    }
}
