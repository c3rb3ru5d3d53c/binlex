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

use crate::disassemblers::arm64::disassembler::Disassembler;

impl<'disassembler> Disassembler<'disassembler> {
    pub(crate) fn read_pointer_sized(&self, address: u64, size: usize) -> Option<u64> {
        let start = self.image_offset(address)?;
        let end = start.checked_add(size)?;
        if end > self.image.len() {
            return None;
        }
        let bytes = &self.image[start..end];
        match size {
            4 => Some(u32::from_le_bytes(bytes.try_into().ok()?) as u64),
            8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
            _ => None,
        }
    }

    pub(crate) fn read_i32(&self, address: u64) -> Option<i32> {
        let start = self.image_offset(address)?;
        let end = start.checked_add(4)?;
        if end > self.image.len() {
            return None;
        }
        let bytes = &self.image[start..end];
        Some(i32::from_le_bytes(bytes.try_into().ok()?))
    }
}
