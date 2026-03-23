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
use ring::digest;
use std::borrow::Cow;

/// Represents a wrapper for computing SHA-256 hashes.
///
/// This struct provides functionality for hashing a byte slice using the SHA-256
/// cryptographic hash algorithm and returning the hash as a hexadecimal string.
pub struct SHA256<'sha256> {
    pub bytes: Cow<'sha256, [u8]>,
}

impl<'sha256> SHA256<'sha256> {
    /// Creates a new `SHA256` instance with the provided byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A reference to the byte slice to be hashed.
    ///
    /// # Returns
    ///
    /// Returns a `SHA256` instance initialized with the provided byte slice.
    #[allow(dead_code)]
    pub fn new(bytes: &'sha256 [u8]) -> Self {
        Self {
            bytes: Cow::Borrowed(bytes),
        }
    }

    #[allow(dead_code)]
    pub fn from_bytes(bytes: Vec<u8>) -> SHA256<'static> {
        SHA256 {
            bytes: Cow::Owned(bytes),
        }
    }

    /// Compares this SHA-256 object against another SHA-256 object.
    pub fn compare(&self, other: &Self) -> Option<f64> {
        let lhs = self.hexdigest()?;
        let rhs = other.hexdigest()?;
        Self::compare_hexdigests(&lhs, &rhs)
    }

    /// Compares this SHA-256 object against a SHA-256 hexdigest.
    pub fn compare_hexdigest(&self, other: &str) -> Option<f64> {
        let lhs = self.hexdigest()?;
        Self::compare_hexdigests(&lhs, other)
    }

    /// Compares two SHA-256 digests.
    pub fn compare_hexdigests(lhs: &str, rhs: &str) -> Option<f64> {
        let lhs = hex::decode(lhs).ok()?;
        let rhs = hex::decode(rhs).ok()?;
        if lhs.len() != rhs.len() || lhs.is_empty() {
            return None;
        }

        Some(if lhs == rhs { 1.0 } else { 0.0 })
    }

    /// Computes the SHA-256 hash of the byte slice and returns it as a hexadecimal string.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hexadecimal representation of the SHA-256 hash.
    /// If the operation fails, it returns `None`. This implementation is currently
    /// designed to always succeed, as `ring::digest` does not fail under normal conditions.
    #[allow(dead_code)]
    pub fn hexdigest(&self) -> Option<String> {
        Some(hex::encode(&self.digest_bytes()))
    }

    /// Computes the SHA-256 hash of the byte slice and returns it as a normalized vector.
    #[allow(dead_code)]
    pub fn vector(&self) -> Option<Vec<f32>> {
        Some(
            self.digest_bytes()
                .iter()
                .map(|byte| *byte as f32 / u8::MAX as f32)
                .collect(),
        )
    }

    fn digest_bytes(&self) -> Vec<u8> {
        digest::digest(&digest::SHA256, self.bytes.as_ref())
            .as_ref()
            .to_vec()
    }
}
