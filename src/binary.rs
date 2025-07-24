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

use std::collections::HashMap;
use std::fmt::Write;

/// A struct representing a binary, used for various binary-related utilities.
pub struct Binary;

impl Binary {
    /// Calculates the entropy of the given byte slice.
    ///
    /// This method computes the Shannon entropy, which is a measure of the randomness
    /// or unpredictability of the data. The entropy value is returned as an `Option<f64>`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A reference to a `Vec<u8>` containing the binary data.
    ///
    /// # Returns
    ///
    /// An `Option<f64>`, where `Some(f64)` is the calculated entropy, or `None` if the data
    /// is empty.
    pub fn entropy(bytes: &Vec<u8>) -> Option<f64> {
        let mut frequency: HashMap<u8, usize> = HashMap::new();
        for &byte in bytes {
            *frequency.entry(byte).or_insert(0) += 1;
        }

        let data_len = bytes.len() as f64;
        if data_len == 0.0 {
            return None;
        }

        let entropy = frequency.values().fold(0.0, |entropy, &count| {
            let probability = count as f64 / data_len;
            entropy - probability * probability.log2()
        });

        Some(entropy)
    }

    /// Converts a byte slice to a hexadecimal string representation.
    ///
    /// This method takes a slice of bytes and returns a `String` where each byte is
    /// represented as a 2-character hexadecimal string.
    ///
    /// # Arguments
    ///
    /// * `data` - A reference to a byte slice (`&[u8]`).
    ///
    /// # Returns
    ///
    /// A `String` containing the hexadecimal representation of the byte data.
    pub fn to_hex(data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for byte in data {
            write!(result, "{:02x}", byte).unwrap();
        }
        result
    }

    pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("hex string has an odd length".to_string());
        }

        hex.as_bytes()
            .chunks(2)
            .map(|chunk| {
                let hex_str =
                    std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string")?;
                u8::from_str_radix(hex_str, 16).map_err(|_| format!("invalid hex: {}", hex_str))
            })
            .collect()
    }

    /// Creates a human-readable hex dump of the provided byte data.
    ///
    /// This method formats the binary data into a string representation with both
    /// hexadecimal values and ASCII characters, often used for debugging or inspecting
    /// binary content.
    ///
    /// # Arguments
    ///
    /// * `data` - A reference to a byte slice (`&[u8]`).
    /// * `address` - The starting memory address (in hexadecimal) to be used in the dump.
    ///
    /// # Returns
    ///
    /// A `String` formatted as a hex dump with both hexadecimal and ASCII views of the data.
    #[allow(dead_code)]
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
            //let hex_values: String = chunk.iter().map(|byte| format!("{:02x} ", byte)).collect();
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
}
