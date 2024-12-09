use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;
use twox_hash::XxHash32;
use std::hash::{Hash, Hasher};

const PRIME_MODULUS: u32 = 4294967291;

/// A MinHash implementation using 32-bit hashes for approximate set similarity calculations.
///
/// This struct provides methods to compute MinHash signatures for a given set of shingles (substrings of fixed size)
/// from a byte slice and to calculate the Jaccard similarity between two MinHash signatures.
pub struct MinHash32 <'minhash32> {
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

impl <'minhash32> MinHash32 <'minhash32> {
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
            a_coefficients: a_coefficients,
            b_coefficients: b_coefficients,
            num_hashes: num_hashes,
            shingle_size: shingle_size,
            bytes: bytes,
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
        if self.bytes.len() < self.shingle_size { return None; }
        let mut min_hashes = vec![u32::MAX; self.num_hashes];
        for shingle in self.bytes.windows(self.shingle_size) {
            let mut hasher = XxHash32::default();
            shingle.hash(&mut hasher);
            let shingle_hash = hasher.finish() as u32;
            for i in 0..self.num_hashes {
                let a = self.a_coefficients[i];
                let b = self.b_coefficients[i];
                let hash_value = (a.wrapping_mul(shingle_hash).wrapping_add(b)) % PRIME_MODULUS;
                if hash_value < min_hashes[i] {
                    min_hashes[i] = hash_value;
                }
            }
        }
        Some(min_hashes)
    }

    /// Computes the Jaccard similarity between two MinHash signatures.
    ///
    /// The similarity is calculated as the ratio of the number of matching hash values
    /// to the total number of hash values.
    ///
    /// # Arguments
    ///
    /// * `hash1` - The first MinHash signature.
    /// * `hash2` - The second MinHash signature.
    ///
    /// # Returns
    ///
    /// Returns a `f64` value representing the Jaccard similarity between the two signatures.
    /// If the signatures have different lengths, it returns `0.0`.
    #[allow(dead_code)]
    pub fn jaccard_similarity(hash1: &[u32], hash2: &[u32]) -> f64 {
        if hash1.len() != hash2.len() { return 0.0; }
        let mut intersection = 0;
        for i in 0..hash1.len() {
            if hash1[i] == hash2[i] {
                intersection += 1;
            }
        }
        intersection as f64 / hash1.len() as f64
    }

    /// Computes the MinHash signature and returns it as a hexadecimal string.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hexadecimal representation of the MinHash signature
    /// if the byte slice is large enough to generate shingles. Returns `None` otherwise.
    pub fn hexdigest(&self) -> Option<String> {
        self.hash().map(|minhash| {
            minhash.iter()
                .map(|hash| format!("{:08x}", hash))
                .collect()
        })
    }
}
