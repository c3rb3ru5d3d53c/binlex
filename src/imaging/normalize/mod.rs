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

mod canvas;
pub(crate) mod exact;
pub(crate) mod fill;
pub(crate) mod filter;
pub(crate) mod fit;

use image::DynamicImage;
use image::imageops::FilterType;

use crate::imaging::Render;

pub(crate) use exact::normalize_exact;
pub(crate) use fill::normalize_fill;
pub(crate) use fit::normalize_fit;

/// A grayscale image stored in row-major order.
pub(crate) struct GrayscaleImage {
    pixels: Vec<u8>,
    width: usize,
    height: usize,
}

impl GrayscaleImage {
    pub(crate) fn new(pixels: Vec<u8>, width: usize, height: usize) -> Self {
        assert_eq!(pixels.len(), width * height);
        Self {
            pixels,
            width,
            height,
        }
    }

    pub(crate) fn from_dynamic_image(image: DynamicImage) -> Self {
        let image = image.into_luma8();
        let width = image.width() as usize;
        let height = image.height() as usize;
        Self::new(image.into_raw(), width, height)
    }

    pub(crate) fn width(&self) -> usize {
        self.width
    }

    pub(crate) fn height(&self) -> usize {
        self.height
    }

    pub(crate) fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    pub(crate) fn get(&self, x: usize, y: usize) -> u8 {
        self.pixels[y * self.width + x]
    }
}

pub(crate) fn decode_grayscale(
    bytes: &[u8],
    width: usize,
    height: usize,
) -> Option<GrayscaleImage> {
    let image = image::load_from_memory(bytes).ok()?;
    let grayscale = image.grayscale();
    let resized = grayscale.resize_exact(width as u32, height as u32, FilterType::Lanczos3);
    Some(GrayscaleImage::from_dynamic_image(resized))
}

#[derive(Clone, Copy)]
pub enum NormalizeAlgorithm {
    Exact(usize, usize),
    Fit(usize, usize),
    Fill(usize, usize),
}

impl NormalizeAlgorithm {
    pub(crate) fn apply(self, render: &Render) -> Render {
        match self {
            Self::Exact(width, height) => normalize_exact(render, width, height),
            Self::Fit(width, height) => normalize_fit(render, width, height),
            Self::Fill(width, height) => normalize_fill(render, width, height),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NormalizeAlgorithm;
    use crate::imaging::{Palette, Render};

    #[test]
    fn exact_normalization_forces_dimensions() {
        let render = Render::new_with_options(&[0, 64, 128, 255], Palette::Grayscale, 1, 2);
        let normalized = NormalizeAlgorithm::Exact(7, 5).apply(&render);
        assert_eq!(normalized.total_width(), 7);
        assert_eq!(normalized.total_height(), 5);
        assert_eq!(normalized.fixed_width(), 7);
    }

    #[test]
    fn fit_normalization_preserves_target_canvas() {
        let render = Render::new_with_options(&[0, 64, 128, 255, 32, 96], Palette::Heatmap, 1, 3);
        let normalized = NormalizeAlgorithm::Fit(8, 8).apply(&render);
        assert_eq!(normalized.total_width(), 8);
        assert_eq!(normalized.total_height(), 8);
        assert_eq!(normalized.total_cells(), 64);
    }

    #[test]
    fn fill_normalization_preserves_target_canvas() {
        let render = Render::new_with_options(&[0, 64, 128, 255, 32, 96], Palette::Bluegreen, 1, 2);
        let normalized = NormalizeAlgorithm::Fill(9, 6).apply(&render);
        assert_eq!(normalized.total_width(), 9);
        assert_eq!(normalized.total_height(), 6);
        assert_eq!(normalized.fixed_width(), 9);
    }
}
