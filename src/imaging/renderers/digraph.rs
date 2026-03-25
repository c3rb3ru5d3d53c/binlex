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

use crate::imaging::palette::Palette;
use crate::imaging::render::{Render, RenderCell};
use std::io::{Error, ErrorKind};

const DIGRAPH_AXIS: usize = 256;

#[derive(Clone)]
enum DigraphIntensity {
    Linear,
    Log,
    Sqrt,
}

impl Default for DigraphIntensity {
    fn default() -> Self {
        Self::Log
    }
}

impl DigraphIntensity {
    fn from_string(value: &str) -> Result<Self, Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            "linear" => Ok(Self::Linear),
            "log" => Ok(Self::Log),
            "sqrt" => Ok(Self::Sqrt),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("'{}' is not a valid digraph intensity", value),
            )),
        }
    }
}

#[derive(Clone)]
pub(crate) struct DigraphRenderer {
    cell_size: usize,
    axis_size: usize,
    stride: usize,
    offset: usize,
    window_size: Option<usize>,
    intensity: DigraphIntensity,
}

impl Default for DigraphRenderer {
    fn default() -> Self {
        Self {
            cell_size: 1,
            axis_size: DIGRAPH_AXIS,
            stride: 1,
            offset: 0,
            window_size: None,
            intensity: DigraphIntensity::default(),
        }
    }
}

impl DigraphRenderer {
    pub(crate) fn new(
        cell_size: Option<usize>,
        axis_size: Option<usize>,
        stride: Option<usize>,
        offset: Option<usize>,
        window_size: Option<usize>,
        intensity: Option<String>,
    ) -> Self {
        let default = Self::default();
        Self {
            cell_size: cell_size.unwrap_or(default.cell_size),
            axis_size: axis_size.unwrap_or(default.axis_size),
            stride: stride.unwrap_or(default.stride),
            offset: offset.unwrap_or(default.offset),
            window_size,
            intensity: intensity
                .as_deref()
                .and_then(|value| DigraphIntensity::from_string(value).ok())
                .unwrap_or(default.intensity),
        }
    }

    pub(crate) fn render(&self, data: &[u8], palette: Palette) -> Render {
        let cell_size = self.cell_size.max(1);
        let axis_size = self.axis_size.max(1);
        let stride = self.stride.max(1);
        let offset = self.offset.min(data.len());
        let end = match self.window_size {
            Some(window_size) => offset.saturating_add(window_size).min(data.len()),
            None => data.len(),
        };
        let mut bins = vec![0usize; axis_size * axis_size];
        let view = &data[offset..end];

        for i in (0..view.len().saturating_sub(1)).step_by(stride) {
            let x = scale_axis(view[i], axis_size);
            let y = scale_axis(view[i + 1], axis_size);
            bins[(y * axis_size) + x] += 1;
        }

        let max_count = bins.iter().copied().max().unwrap_or(0);
        let total_cells = axis_size * axis_size;
        let total_width = axis_size * cell_size;
        let total_height = axis_size * cell_size;
        let mut cells = Vec::with_capacity(total_cells);

        for (index, count) in bins.into_iter().enumerate() {
            let x = index % axis_size;
            let y = index / axis_size;
            let normalized = normalize_count(count, max_count, &self.intensity);

            cells.push(RenderCell::new(
                index,
                index as u64,
                x * cell_size,
                y * cell_size,
                cell_size,
                cell_size,
                palette.map_byte_rgb(normalized),
            ));
        }

        Render::from_cells(cells, total_width, total_height, total_cells, axis_size)
    }
}

fn scale_axis(byte: u8, axis_size: usize) -> usize {
    if axis_size <= 1 {
        return 0;
    }

    ((byte as usize) * axis_size) / DIGRAPH_AXIS
}

fn normalize_count(count: usize, max_count: usize, intensity: &DigraphIntensity) -> u8 {
    if max_count == 0 || count == 0 {
        return 0;
    }

    let scaled = match intensity {
        DigraphIntensity::Linear => count as f64 / max_count as f64,
        DigraphIntensity::Log => (count as f64).ln_1p() / (max_count as f64).ln_1p(),
        DigraphIntensity::Sqrt => (count as f64).sqrt() / (max_count as f64).sqrt(),
    };
    let normalized = (scaled * 255.0).round() as usize;
    normalized.clamp(16, 255) as u8
}
