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
use crate::imaging::render::Render;
use image::ColorType;
use image::ImageEncoder;
use image::RgbaImage;
use image::codecs::png::PngEncoder;
use std::io;

pub struct PNG {
    render: Render,
}

impl PNG {
    pub fn new(data: &[u8], palette: Palette) -> Self {
        Self::new_with_options(data, palette, 1, 16)
    }

    pub fn new_with_options(
        data: &[u8],
        palette: Palette,
        cell_size: usize,
        fixed_width: usize,
    ) -> Self {
        Self::from_render(Render::new_with_options(
            data,
            palette,
            cell_size,
            fixed_width,
        ))
    }

    pub(crate) fn from_render(render: Render) -> Self {
        Self { render }
    }

    pub fn bytes(&self) -> io::Result<Vec<u8>> {
        let width = u32::try_from(self.render.total_width()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "png width exceeds u32 range")
        })?;
        let height = u32::try_from(self.render.total_height()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "png height exceeds u32 range")
        })?;

        if width == 0 || height == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "png output requires non-empty image dimensions",
            ));
        }

        let mut rgba = RgbaImage::new(width, height);

        for cell in self.render.cells() {
            let (r, g, b) = cell.rgb();

            for y in cell.y()..(cell.y() + cell.height()) {
                for x in cell.x()..(cell.x() + cell.width()) {
                    rgba.put_pixel(x as u32, y as u32, image::Rgba([r, g, b, 255]));
                }
            }
        }

        let mut encoded = Vec::new();
        let encoder = PngEncoder::new(&mut encoded);
        encoder
            .write_image(rgba.as_raw(), width, height, ColorType::Rgba8.into())
            .map_err(|error| io::Error::other(error.to_string()))?;

        Ok(encoded)
    }

    pub fn write(&self, file_path: &str) -> io::Result<()> {
        std::fs::write(file_path, self.bytes()?)
    }
}
