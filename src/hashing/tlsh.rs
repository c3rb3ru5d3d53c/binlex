use tlsh;
use std::io::Error;
use std::io::ErrorKind;

/// Represents a wrapper around the TLSH (Trend Micro Locality Sensitive Hash) functionality.
///
/// This struct provides functionality for creating TLSH hashes from a slice of bytes with a minimum
/// byte size requirement, which ensures only sufficiently large data is hashed.
pub struct TLSH <'tlsh> {
    /// The slice of bytes to be hashed.
    pub bytes: &'tlsh [u8],
    /// The minimum required byte size for hashing.
    pub mininum_byte_size: usize,
}

impl <'tlsh> TLSH <'tlsh> {
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
            bytes: bytes,
            mininum_byte_size: mininum_byte_size,
        }
    }


    /// Compares two hexdigests and get the simialrity score between 0 and 1 where 0 is not similar and 1 is the same.
    ///
    /// # Returns
    ///
    /// Returns a `Result<u32, Error>` where the `u32` is the similarity score and `Error` if compare fails.
    pub fn compare(lhs: String, rhs: String) -> Result<u32, Error> {
        tlsh::compare(&lhs, &rhs)
            .map_err(|e| Error::new(ErrorKind::Other, e))
    }

    /// Computes the TLSH hash of the byte slice if it meets the minimum size requirement.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hexadecimal digest of the TLSH hash if the byte slice
    /// length is greater than or equal to `mininum_byte_size`. Returns `None` otherwise.
    #[allow(dead_code)]
    pub fn hexdigest(&self) -> Option<String> {
        if self.bytes.len() < self.mininum_byte_size { return None; }
        tlsh::hash_buf(&self.bytes).ok().map(|h| h.to_string())
    }

}
