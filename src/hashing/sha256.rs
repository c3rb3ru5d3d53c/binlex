use ring::digest;
use crate::binary::Binary;

/// Represents a wrapper for computing SHA-256 hashes.
///
/// This struct provides functionality for hashing a byte slice using the SHA-256
/// cryptographic hash algorithm and returning the hash as a hexadecimal string.
pub struct SHA256 <'sha256> {
    pub bytes: &'sha256 [u8],
}

impl <'sha256> SHA256 <'sha256> {
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
            bytes: bytes
        }
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
        let digest = digest::digest(&digest::SHA256, &self.bytes);
        return Some(Binary::to_hex(digest.as_ref()));
    }
}
