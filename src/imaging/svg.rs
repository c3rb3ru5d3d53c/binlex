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
use std::fmt;
use std::io::{self, Write};

struct Cell {
    index: usize,
    address: u64,
    rgb: (u8, u8, u8),
}

pub struct SVG {
    metadata_entries: Vec<(String, String)>,
    cells: Vec<Cell>,
    total_cells: usize,
    cell_size: usize,
    fixed_width: usize,
}

impl SVG {
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
        let mut cells = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            cells.push(Cell {
                index: i,
                address: i as u64,
                rgb: palette.map_byte_rgb(byte),
            });
        }

        Self {
            metadata_entries: Vec::new(),
            cells,
            total_cells: data.len(),
            cell_size,
            fixed_width,
        }
    }

    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata_entries.push((key, value));
    }

    fn generate_metadata(&self) -> String {
        if self.metadata_entries.is_empty() {
            return String::new();
        }

        let mut metadata_section = String::from("<metadata>\n");
        for (key, value) in &self.metadata_entries {
            metadata_section.push_str(&format!("<{}>{}</{}>\n", key, value, key));
        }
        metadata_section.push_str("</metadata>\n");
        metadata_section
    }

    pub fn write(&self, file_path: &str) -> Result<(), std::io::Error> {
        std::fs::write(file_path, self.to_string())
    }

    pub fn print(&self) -> io::Result<()> {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        self.write_terminal(&mut stdout)
    }

    pub fn write_terminal<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        if self.total_cells == 0 {
            write!(writer, "\x1b[0m")?;
            return Ok(());
        }

        let row_count = self.total_cells.div_ceil(self.fixed_width);

        for row in 0..row_count {
            let start = row * self.fixed_width;
            let end = (start + self.fixed_width).min(self.total_cells);

            for cell in &self.cells[start..end] {
                let (r, g, b) = cell.rgb;
                write!(writer, "\x1b[48;5;{}m  ", rgb_to_ansi256(r, g, b))?;
            }

            writeln!(writer, "\x1b[0m")?;
        }

        write!(writer, "\x1b[0m")?;
        writer.flush()
    }

    fn total_height(&self) -> usize {
        self.total_cells.div_ceil(self.fixed_width) * self.cell_size
    }
}

impl fmt::Display for SVG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_width = self.fixed_width * self.cell_size;
        let total_height = self.total_height();

        write!(
            f,
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">
"#,
            total_width, total_height, total_width, total_height
        )?;

        write!(f, "{}", self.generate_metadata())?;

        for cell in &self.cells {
            let row = cell.index / self.fixed_width;
            let col = cell.index % self.fixed_width;
            let x = col * self.cell_size;
            let y = row * self.cell_size;
            let (r, g, b) = cell.rgb;

            write!(
                f,
                r#"<rect x="{}" y="{}" width="{}" height="{}" fill="rgb({},{},{})" cell-index="{}" address="{}"/>
"#,
                x, y, self.cell_size, self.cell_size, r, g, b, cell.index, cell.address
            )?;
        }

        writeln!(f, "</svg>")
    }
}

fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
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

#[cfg(test)]
mod tests {
    use super::{SVG, rgb_to_ansi256};
    use crate::imaging::Palette;

    #[test]
    fn terminal_output_uses_rows_and_resets() {
        let svg = SVG::new_with_options(&[0x00, 0x7f, 0xff], Palette::Grayscale, 1, 2);
        let mut buffer = Vec::new();

        svg.write_terminal(&mut buffer).unwrap();

        let output = String::from_utf8(buffer).unwrap();
        assert_eq!(output.matches('\n').count(), 2);
        assert!(output.ends_with("\x1b[0m"));
        assert_eq!(output.matches("\x1b[48;5;").count(), 3);
    }

    #[test]
    fn display_renders_metadata_and_cells() {
        let mut svg = SVG::new_with_options(&[0x10], Palette::Redblack, 3, 4);
        svg.add_metadata("Hash".to_string(), "sha256:test".to_string());

        let output = svg.to_string();

        assert!(output.contains("<metadata>"));
        assert!(output.contains("fill=\"rgb(16,0,0)\""));
        assert!(output.contains("width=\"12\" height=\"3\""));
    }

    #[test]
    fn rgb_to_ansi256_maps_grayscale_and_color_cube() {
        assert_eq!(rgb_to_ansi256(0, 0, 0), 16);
        assert_eq!(rgb_to_ansi256(255, 255, 255), 231);
        assert_eq!(rgb_to_ansi256(128, 128, 128), 243);
        assert_eq!(rgb_to_ansi256(255, 0, 0), 196);
    }
}
