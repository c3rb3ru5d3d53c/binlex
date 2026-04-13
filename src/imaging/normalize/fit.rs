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

use image::imageops::{overlay, resize};
use image::{Rgba, RgbaImage};

use crate::imaging::Render;
use crate::imaging::normalize::canvas::{image_to_render, render_to_image};
use crate::imaging::normalize::filter::DEFAULT_FILTER;

pub(crate) fn normalize_fit(render: &Render, width: usize, height: usize) -> Render {
    let target_width = width.max(1);
    let target_height = height.max(1);
    let source = render_to_image(render);
    let (scaled_width, scaled_height) = fit_dimensions(
        source.width() as usize,
        source.height() as usize,
        target_width,
        target_height,
    );
    let resized = resize(
        &source,
        scaled_width as u32,
        scaled_height as u32,
        DEFAULT_FILTER,
    );
    let mut canvas = RgbaImage::from_pixel(
        target_width as u32,
        target_height as u32,
        Rgba([0, 0, 0, 255]),
    );
    let x = ((target_width - scaled_width) / 2) as i64;
    let y = ((target_height - scaled_height) / 2) as i64;
    overlay(&mut canvas, &resized, x, y);
    image_to_render(canvas)
}

fn fit_dimensions(
    source_width: usize,
    source_height: usize,
    target_width: usize,
    target_height: usize,
) -> (usize, usize) {
    scale_dimensions(
        source_width,
        source_height,
        target_width,
        target_height,
        ScaleMode::Fit,
    )
}

pub(crate) enum ScaleMode {
    Fit,
    Fill,
}

pub(crate) fn scale_dimensions(
    source_width: usize,
    source_height: usize,
    target_width: usize,
    target_height: usize,
    mode: ScaleMode,
) -> (usize, usize) {
    let source_width = source_width.max(1) as f64;
    let source_height = source_height.max(1) as f64;
    let target_width = target_width.max(1) as f64;
    let target_height = target_height.max(1) as f64;
    let width_ratio = target_width / source_width;
    let height_ratio = target_height / source_height;
    let scale = match mode {
        ScaleMode::Fit => width_ratio.min(height_ratio),
        ScaleMode::Fill => width_ratio.max(height_ratio),
    };
    let scaled_width = (source_width * scale).round().max(1.0) as usize;
    let scaled_height = (source_height * scale).round().max(1.0) as usize;
    (scaled_width, scaled_height)
}

pub(crate) fn resize_with_default_filter(
    source: &RgbaImage,
    width: usize,
    height: usize,
) -> RgbaImage {
    resize(
        source,
        width.max(1) as u32,
        height.max(1) as u32,
        DEFAULT_FILTER,
    )
}
