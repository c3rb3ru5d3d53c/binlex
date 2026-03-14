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

use std::fmt::Write;

pub fn hexdump(data: &[u8], address: u64) -> String {
    const BYTES_PER_LINE: usize = 16;
    let mut result = String::new();
    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        let current_address = address as usize + i * BYTES_PER_LINE;
        let hex_repr = format!("{:08x}: ", current_address);
        result.push_str(&hex_repr);
        let hex_values = {
            let mut s = String::new();
            for byte in chunk {
                let _ = write!(s, "{:02x} ", byte);
            }
            s
        };
        result.push_str(&hex_values);
        let padding = "   ".repeat(BYTES_PER_LINE - chunk.len());
        result.push_str(&padding);
        let ascii_values: String = chunk
            .iter()
            .map(|&byte| {
                if byte.is_ascii_graphic() || byte == b' ' {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect();
        result.push('|');
        result.push_str(&ascii_values);
        result.push_str("|\n");
    }
    result
}
