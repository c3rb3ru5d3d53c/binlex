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

use super::*;

mod extract_insert;
mod masks;
mod permute;
mod unpack;

pub(super) use extract_insert::*;
pub(super) use masks::*;
pub(super) use permute::*;
pub(super) use unpack::*;

fn shuffle_dwords(bits: u16, src: &SemanticExpression, imm: u8) -> Option<SemanticExpression> {
    if bits < 128 {
        return None;
    }
    let mut parts = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(src, 32, select));
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn shuffle_words_half(
    bits: u16,
    src: &SemanticExpression,
    imm: u8,
    high_half: bool,
) -> Option<SemanticExpression> {
    if bits < 128 {
        return None;
    }
    let base_lane = if high_half { 4 } else { 0 };
    let other_base = if high_half { 0 } else { 4 };
    let mut shuffled_half = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        shuffled_half.push(extract_lane(src, 16, base_lane + select));
    }
    let mut parts = Vec::with_capacity(8);
    if high_half {
        parts.extend(shuffled_half);
        for lane in (0..4).rev() {
            parts.push(extract_lane(src, 16, other_base + lane));
        }
    } else {
        for lane in (0..4).rev() {
            parts.push(extract_lane(src, 16, other_base + lane));
        }
        parts.extend(shuffled_half);
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn shuffle_words(bits: u16, src: &SemanticExpression, imm: u8) -> Option<SemanticExpression> {
    if bits != 64 {
        return None;
    }
    let mut parts = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(src, 16, select));
    }
    Some(SemanticExpression::Concat { parts, bits })
}
