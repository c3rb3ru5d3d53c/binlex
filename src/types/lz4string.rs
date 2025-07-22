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

use lz4::block::{compress, decompress};
use std::convert::From;

/// A structure representing a compressed string using the LZ4 compression algorithm.
pub struct LZ4String {
    /// The compressed representation of the string.
    compressed_data: Vec<u8>,
    /// The size of the original uncompressed string.
    uncompressed_size: usize,
}

impl LZ4String {
    /// Creates a new `LZ4String` from a given string slice.
    ///
    /// # Arguments
    ///
    /// * `data` - The string slice to compress.
    ///
    /// # Returns
    ///
    /// A new `LZ4String` containing the compressed data and the original size.
    ///
    /// # Panics
    ///
    /// This function will panic if the compression operation fails.
    #[allow(dead_code)]
    pub fn new(data: &str) -> Self {
        let compressed =
            compress(data.as_bytes(), None, false).expect("lz4string compression failed");
        LZ4String {
            compressed_data: compressed,
            uncompressed_size: data.len(),
        }
    }

    /// Decompresses the `LZ4String` back into its original string representation.
    ///
    /// # Returns
    ///
    /// The original uncompressed string.
    ///
    /// # Panics
    ///
    /// This function will panic if the decompression operation fails or if the decompressed data is not valid UTF-8.
    #[allow(dead_code)]
    pub fn decompress_to_string(&self) -> String {
        let decompressed = decompress(&self.compressed_data, Some(self.uncompressed_size as i32))
            .expect("lz4string decompression failed");
        String::from_utf8(decompressed).expect("lz4string invalid utf8")
    }
}

impl From<String> for LZ4String {
    /// Converts a `String` into an `LZ4String`.
    ///
    /// # Arguments
    ///
    /// * `data` - The string to compress.
    ///
    /// # Returns
    ///
    /// An `LZ4String` containing the compressed data and the original size.
    ///
    /// # Panics
    ///
    /// This function will panic if the compression operation fails.
    fn from(data: String) -> Self {
        let compressed =
            compress(data.as_bytes(), None, false).expect("lz4string compression failed");
        LZ4String {
            compressed_data: compressed,
            uncompressed_size: data.len(),
        }
    }
}

impl std::fmt::Display for LZ4String {
    /// Formats the `LZ4String` by decompressing it and writing the original string to the formatter.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter to write the decompressed string to.
    ///
    /// # Returns
    ///
    /// A result indicating whether the operation was successful.
    ///
    /// # Panics
    ///
    /// This method will panic if the decompression operation fails or if the decompressed data is not valid UTF-8.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.decompress_to_string();
        write!(f, "{}", s)
    }
}
