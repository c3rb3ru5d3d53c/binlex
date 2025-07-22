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

use tlsh;

/// Represents a wrapper around the TLSH (Trend Micro Locality Sensitive Hash) functionality.
///
/// This struct provides functionality for creating TLSH hashes from a slice of bytes with a minimum
/// byte size requirement, which ensures only sufficiently large data is hashed.
pub struct TLSH<'tlsh> {
    /// The slice of bytes to be hashed.
    pub bytes: &'tlsh [u8],
    /// The minimum required byte size for hashing.
    pub mininum_byte_size: usize,
}

impl<'tlsh> TLSH<'tlsh> {
    /// Creates a new `TLSH` instance with the provided bytes and minimum byte size.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A reference to the byte slice that will be hashed.
    /// * `mininum_byte_size` - The minimum size of `bytes` required for hashing.
    ///
    /// # Returns
    ///
    /// Returns a `TLSH` instance initialized with the provided byte slice and minimum byte size.
    #[allow(dead_code)]
    pub fn new(bytes: &'tlsh [u8], mininum_byte_size: usize) -> Self {
        Self {
            bytes,
            mininum_byte_size,
        }
    }

    /// Compares two hexdigests and get the simialrity score between 0 and 1 where 0 is not similar and 1 is the same.
    ///
    /// # Returns
    ///
    /// Returns a `Result<u32, Error>` where the `u32` is the similarity score and `Error` if compare fails.
    pub fn compare(lhs: String, rhs: String) -> Option<f64> {
        tlsh::compare(&lhs, &rhs)
            .map(|value| value as f64) // Convert the u32 to f64
            .ok()
    }

    /// Computes the TLSH hash of the byte slice if it meets the minimum size requirement.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hexadecimal digest of the TLSH hash if the byte slice
    /// length is greater than or equal to `mininum_byte_size`. Returns `None` otherwise.
    #[allow(dead_code)]
    pub fn hexdigest(&self) -> Option<String> {
        if self.bytes.len() < self.mininum_byte_size {
            return None;
        }
        tlsh::hash_buf(self.bytes).ok().map(|h| h.to_string())
    }
}
