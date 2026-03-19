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
use crate::imaging::normalize::decode_grayscale;

pub struct DHash<'dhash> {
    pub bytes: &'dhash [u8],
}

impl<'dhash> DHash<'dhash> {
    #[allow(dead_code)]
    pub fn new(bytes: &'dhash [u8]) -> Self {
        Self { bytes }
    }

    pub fn compare(&self, other: &Self) -> Option<f64> {
        let lhs = self.hexdigest()?;
        let rhs = other.hexdigest()?;
        Self::compare_hexdigests(&lhs, &rhs)
    }

    pub fn compare_hexdigest(&self, other: &str) -> Option<f64> {
        let lhs = self.hexdigest()?;
        Self::compare_hexdigests(&lhs, other)
    }

    pub fn compare_hexdigests(lhs: &str, rhs: &str) -> Option<f64> {
        compare_hex_digests(lhs, rhs)
    }

    #[allow(dead_code)]
    pub fn hexdigest(&self) -> Option<String> {
        let image = decode_grayscale(self.bytes, 9, 8)?;
        let mut bits = Vec::with_capacity(64);

        for y in 0..8 {
            for x in 0..8 {
                bits.push(image.get(x + 1, y) > image.get(x, y));
            }
        }

        Some(hex::encode(&pack_bits(&bits)))
    }
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
