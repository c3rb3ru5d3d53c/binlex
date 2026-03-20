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

use crate::config::{Config, ConfigImaging};
use crate::imaging::Palette;
use crate::imaging::hash as render_hash;
use crate::imaging::render::Render;
use crate::imaging::terminal::write_render;
use std::fmt;
use std::io::{self, Write};

pub struct SVG {
    hashing: ConfigImaging,
    metadata_entries: Vec<(String, String)>,
    render: Render,
}

impl SVG {
    pub fn new(data: &[u8], palette: Palette, config: Config) -> Self {
        Self::with_options(data, palette, 1, 16, config)
    }

    pub fn with_options(
        data: &[u8],
        palette: Palette,
        cell_size: usize,
        fixed_width: usize,
        config: Config,
    ) -> Self {
        Self::from_render(
            Render::new_with_options(data, palette, cell_size, fixed_width),
            config.imaging.clone(),
        )
    }

    pub(crate) fn from_render(render: Render, hashing: ConfigImaging) -> Self {
        Self {
            hashing,
            metadata_entries: Vec::new(),
            render,
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

    pub fn png_bytes(&self) -> io::Result<Vec<u8>> {
        render_hash::encode_png(&self.render)
    }

    pub fn print(&self) -> io::Result<()> {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        self.write_terminal(&mut stdout)
    }

    pub fn print_svg(&self) -> io::Result<()> {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        write!(stdout, "{}", self)?;
        stdout.flush()
    }

    pub fn write_terminal<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        write_render(&self.render, writer)
    }

    pub fn sha256(&self) -> Option<String> {
        render_hash::sha256(&self.render, &self.hashing)
    }

    pub fn tlsh(&self) -> Option<String> {
        render_hash::tlsh(&self.render, &self.hashing)
    }

    pub fn minhash(&self) -> Option<String> {
        render_hash::minhash(&self.render, &self.hashing)
    }

    pub fn ahash(&self) -> Option<String> {
        render_hash::ahash(&self.render, &self.hashing)
    }

    pub fn dhash(&self) -> Option<String> {
        render_hash::dhash(&self.render, &self.hashing)
    }

    pub fn phash(&self) -> Option<String> {
        render_hash::phash(&self.render, &self.hashing)
    }
}

impl fmt::Display for SVG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total_width = self.render.total_width();
        let total_height = self.render.total_height();

        write!(
            f,
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">
"#,
            total_width, total_height, total_width, total_height
        )?;

        write!(f, "{}", self.generate_metadata())?;

        for cell in self.render.cells() {
            let (r, g, b) = cell.rgb();

            write!(
                f,
                r#"<rect x="{}" y="{}" width="{}" height="{}" fill="rgb({},{},{})" cell-index="{}" address="{}"/>
"#,
                cell.x(),
                cell.y(),
                cell.width(),
                cell.height(),
                r,
                g,
                b,
                cell.index(),
                cell.address()
            )?;
        }

        writeln!(f, "</svg>")
    }
}
