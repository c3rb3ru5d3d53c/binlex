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

use image::RgbaImage;

use crate::imaging::render::{Render, RenderCell};

fn clamp_dimension(value: usize) -> usize {
    value.max(1)
}

pub(crate) fn render_to_image(render: &Render) -> RgbaImage {
    let width = clamp_dimension(render.total_width()) as u32;
    let height = clamp_dimension(render.total_height()) as u32;
    let mut rgba = RgbaImage::new(width, height);

    for cell in render.cells() {
        let (r, g, b) = cell.rgb();

        for y in cell.y()..(cell.y() + cell.height()) {
            for x in cell.x()..(cell.x() + cell.width()) {
                if x < render.total_width() && y < render.total_height() {
                    rgba.put_pixel(x as u32, y as u32, image::Rgba([r, g, b, 255]));
                }
            }
        }
    }

    rgba
}

pub(crate) fn image_to_render(image: RgbaImage) -> Render {
    let width = clamp_dimension(image.width() as usize);
    let height = clamp_dimension(image.height() as usize);
    let total_cells = width * height;
    let mut cells = Vec::with_capacity(total_cells);

    for (index, pixel) in image.pixels().enumerate() {
        let x = index % width;
        let y = index / width;
        cells.push(RenderCell::new(
            index,
            index as u64,
            x,
            y,
            1,
            1,
            (pixel[0], pixel[1], pixel[2]),
        ));
    }

    Render::from_cells(cells, width, height, total_cells, width)
}
