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

use image::imageops::crop_imm;

use crate::imaging::Render;
use crate::imaging::normalize::canvas::{image_to_render, render_to_image};
use crate::imaging::normalize::fit::{resize_with_default_filter, scale_dimensions};

pub(crate) fn normalize_fill(render: &Render, width: usize, height: usize) -> Render {
    let target_width = width.max(1);
    let target_height = height.max(1);
    let source = render_to_image(render);
    let (scaled_width, scaled_height) = scale_dimensions(
        source.width() as usize,
        source.height() as usize,
        target_width,
        target_height,
        super::fit::ScaleMode::Fill,
    );
    let resized = resize_with_default_filter(&source, scaled_width, scaled_height);
    let x = ((scaled_width - target_width) / 2) as u32;
    let y = ((scaled_height - target_height) / 2) as u32;
    let cropped = crop_imm(&resized, x, y, target_width as u32, target_height as u32).to_image();
    image_to_render(cropped)
}
