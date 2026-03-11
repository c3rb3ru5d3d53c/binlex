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

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use std::hash::{Hash, Hasher};
use twox_hash::XxHash32;

const PRIME_MODULUS: u32 = 4294967291;

/// A MinHash implementation using 32-bit hashes for approximate set similarity calculations.
///
/// This struct provides methods to compute MinHash signatures for a given set of shingles (substrings of fixed size)
/// from a byte slice and to calculate the Jaccard similarity between two MinHash signatures.
pub struct MinHash32<'minhash32> {
    /// Coefficients for the linear hash functions used in MinHash.
    a_coefficients: Vec<u32>,
    /// Intercept coefficients for the linear hash functions used in MinHash.
    b_coefficients: Vec<u32>,
    /// The number of hash functions to use for MinHash.
    num_hashes: usize,
    /// The size of shingles (substrings) used to compute MinHash.
    shingle_size: usize,
    /// The byte slice to be hashed.
    bytes: &'minhash32 [u8],
}

impl<'minhash32> MinHash32<'minhash32> {
    /// Creates a new `MinHash32` instance with the provided parameters.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A reference to the byte slice to be hashed.
    /// * `num_hashes` - The number of hash functions to use for MinHash.
    /// * `shingle_size` - The size of shingles (substrings) used to compute MinHash.
    /// * `seed` - A seed for the random number generator to ensure deterministic coefficients.
    ///
    /// # Returns
    ///
    /// Returns a `MinHash32` instance initialized with the provided parameters and
    /// randomly generated coefficients for the hash functions.
    pub fn new(bytes: &'minhash32 [u8], num_hashes: usize, shingle_size: usize, seed: u64) -> Self {
        let mut rng = SmallRng::seed_from_u64(seed);
        let max_hash: u32 = u32::MAX;
        let mut a_coefficients = Vec::with_capacity(num_hashes);
        let mut b_coefficients = Vec::with_capacity(num_hashes);

        for _ in 0..num_hashes {
            a_coefficients.push(rng.gen_range(1..max_hash));
            b_coefficients.push(rng.gen_range(0..max_hash));
        }

        Self {
            a_coefficients,
            b_coefficients,
            num_hashes,
            shingle_size,
            bytes,
        }
    }

    /// Computes the MinHash signature for the byte slice.
    ///
    /// The signature is computed by applying multiple hash functions to each shingle
    /// and taking the minimum hash value for each function across all shingles.
    ///
    /// # Returns
    ///
    /// Returns `Some(Vec<u32>)` containing the MinHash signature if the byte slice is large enough
    /// to generate shingles of the specified size. Returns `None` otherwise.
    pub fn hash(&self) -> Option<Vec<u32>> {
        if self.bytes.len() < self.shingle_size {
            return None;
        }
        let mut min_hashes = vec![u32::MAX; self.num_hashes];
        for shingle in self.bytes.windows(self.shingle_size) {
            let mut hasher = XxHash32::default();
            shingle.hash(&mut hasher);
            let shingle_hash = hasher.finish() as u32;
            for ((a, b), min) in self
                .a_coefficients
                .iter()
                .zip(&self.b_coefficients)
                .zip(&mut min_hashes)
            {
                let hash_value = (a.wrapping_mul(shingle_hash).wrapping_add(*b)) % PRIME_MODULUS;
                if hash_value < *min {
                    *min = hash_value;
                }
            }
        }
        Some(min_hashes)
    }

    /// Computes the MinHash signature and returns it as a hexadecimal string.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hexadecimal representation of the MinHash signature
    /// if the byte slice is large enough to generate shingles. Returns `None` otherwise.
    pub fn hexdigest(&self) -> Option<String> {
        self.hash().map(|minhash| {
            minhash
                .iter()
                .map(|h| format!("{:08x}", h))
                .collect::<Vec<_>>()
                .join("")
        })
    }
}
