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

use crate::hex;
use crate::imaging::normalize::{GrayscaleImage, decode_grayscale};
use std::f64::consts::PI;

pub struct PHash<'phash> {
    pub bytes: &'phash [u8],
}

impl<'phash> PHash<'phash> {
    #[allow(dead_code)]
    pub fn new(bytes: &'phash [u8]) -> Self {
        Self { bytes }
    }

    pub fn compare(lhs: &str, rhs: &str) -> Option<f64> {
        compare_hex_digests(lhs, rhs)
    }

    #[allow(dead_code)]
    pub fn hexdigest(&self) -> Option<String> {
        let image = decode_grayscale(self.bytes, 32, 32)?;
        let dct = dct_2d(&image);

        let mut low_frequencies = Vec::with_capacity(64);
        for y in 0..8 {
            for x in 0..8 {
                if x == 0 && y == 0 {
                    continue;
                }
                low_frequencies.push(dct[y * 32 + x]);
            }
        }

        let mean = low_frequencies.iter().sum::<f64>() / low_frequencies.len() as f64;
        let mut bits = Vec::with_capacity(64);

        for y in 0..8 {
            for x in 0..8 {
                let coefficient = dct[y * 32 + x];
                if x == 0 && y == 0 {
                    bits.push(coefficient > mean);
                    continue;
                }
                bits.push(coefficient > mean);
            }
        }

        Some(hex::encode(&pack_bits(&bits)))
    }
}

fn dct_2d(image: &GrayscaleImage) -> Vec<f64> {
    let width = image.width();
    let height = image.height();
    let mut coefficients = vec![0.0; width * height];

    for v in 0..height {
        for u in 0..width {
            let mut sum = 0.0;
            for y in 0..height {
                for x in 0..width {
                    let pixel = image.get(x, y) as f64;
                    let cos_x = (((2 * x + 1) as f64 * u as f64 * PI) / (2.0 * width as f64)).cos();
                    let cos_y =
                        (((2 * y + 1) as f64 * v as f64 * PI) / (2.0 * height as f64)).cos();
                    sum += pixel * cos_x * cos_y;
                }
            }

            let alpha_u = if u == 0 {
                (1.0 / width as f64).sqrt()
            } else {
                (2.0 / width as f64).sqrt()
            };
            let alpha_v = if v == 0 {
                (1.0 / height as f64).sqrt()
            } else {
                (2.0 / height as f64).sqrt()
            };

            coefficients[v * width + u] = alpha_u * alpha_v * sum;
        }
    }

    coefficients
}

fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0; bits.len().div_ceil(8)];
    for (index, bit) in bits.iter().enumerate() {
        if *bit {
            bytes[index / 8] |= 1 << (7 - (index % 8));
        }
    }
    bytes
}

fn compare_hex_digests(lhs: &str, rhs: &str) -> Option<f64> {
    let lhs = hex::decode(lhs).ok()?;
    let rhs = hex::decode(rhs).ok()?;
    if lhs.len() != rhs.len() || lhs.is_empty() {
        return None;
    }

    let differing_bits = lhs
        .iter()
        .zip(rhs.iter())
        .map(|(lhs, rhs)| (lhs ^ rhs).count_ones())
        .sum::<u32>() as f64;
    let total_bits = (lhs.len() * 8) as f64;
    Some(1.0 - (differing_bits / total_bits))
}
