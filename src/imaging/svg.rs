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

pub struct SVG {
    metadata_entries: Vec<(String, String)>,
    rectangles: Vec<String>,
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
        let mut rectangles = Vec::with_capacity(data.len());

        for (i, &byte) in data.iter().enumerate() {
            let row = i / fixed_width;
            let col = i % fixed_width;
            let x = col * cell_size;
            let y = row * cell_size;
            let color = palette.map_byte(byte);

            rectangles.push(format!(
                r#"<rect x="{}" y="{}" width="{}" height="{}" fill="{}" cell-index="{}" address="{}"/>
"#,
                x, y, cell_size, cell_size, color, i, i as u64
            ));
        }

        Self {
            metadata_entries: Vec::new(),
            rectangles,
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
}

impl fmt::Display for SVG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_width = self.fixed_width * self.cell_size;
        let total_height = ((self.total_cells as f64) / (self.fixed_width as f64)).ceil() as usize
            * self.cell_size;

        write!(
            f,
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">
"#,
            total_width, total_height, total_width, total_height
        )?;

        write!(f, "{}", self.generate_metadata())?;

        for rectangle in &self.rectangles {
            write!(f, "{}", rectangle)?;
        }

        writeln!(f, "</svg>")
    }
}
