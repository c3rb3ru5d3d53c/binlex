use serde::{Deserialize, Serialize};
use serde_json;
use std::io::Error;
use std::io::ErrorKind;
use crate::binary::Binary;
use crate::hashing::SHA256;
use crate::hashing::TLSH;
use crate::hashing::MinHash32;
use crate::controlflow::AllelePair;
use crate::controlflow::Gene;
use crate::Config;

/// Represents a JSON-serializable structure containing metadata about a chromosome.
#[derive(Serialize, Deserialize)]
pub struct ChromosomeJson {
    /// The raw pattern string of the chromosome.
    pub pattern: String,
    /// The feature vector extracted from the chromosome.
    pub feature: Vec<u8>,
    /// The entropy of the normalized chromosome, if enabled.
    pub entropy: Option<f64>,
    /// The SHA-256 hash of the normalized chromosome, if enabled.
    pub sha256: Option<String>,
    /// The MinHash of the normalized chromosome, if enabled.
    pub minhash: Option<String>,
    /// The TLSH (Locality Sensitive Hash) of the normalized chromosome, if enabled.
    pub tlsh: Option<String>,
}

/// Represents a chromosome within a control flow graph.
pub struct Chromosome {
    pub pairs: Vec<AllelePair>,
    config: Config,
}

impl Chromosome {
    /// Creates a new `Chromosome` instance for a specified address range within a control flow graph.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The chromosome pattern string.
    /// * `config` - The configuraiton.
    ///
    /// # Returns
    ///
    /// Returns `Result<Chromosome, Error>`.
    pub fn new(pattern: String, config: Config) -> Result<Self, Error> {
        let pairs = Self::parse_pairs(pattern)?;
        Ok(Self {
            pairs: pairs,
            config: config,
        })
    }

    #[allow(dead_code)]
    fn parse_pairs(pattern: String) -> Result<Vec<AllelePair>, Error> {
        if pattern.len() % 2 != 0 {
            return Err(Error::new(ErrorKind::InvalidData, format!("pattern length must be even")));
        }
        let mut parsed = Vec::new();
        let chars: Vec<char> = pattern.chars().collect();
        for chunk in chars.chunks(2) {
            let high = Self::parse_gene(chunk[0])?;
            let low = Self::parse_gene(chunk[1])?;
            parsed.push(AllelePair { high, low });
        }
        Ok(parsed)
    }

    fn parse_gene(c: char) -> Result<Gene, Error> {
        match c {
            '?' => Ok(Gene::Wildcard),
            _ if c.is_ascii_hexdigit() => {
                let value = u8::from_str_radix(&c.to_string(), 16)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, format!("invalid genene hexidecimal value")))?;
                Ok(Gene::Value(value))
            }
            _ => Err(Error::new(ErrorKind::InvalidData, "invalid character in gene")),
        }
    }

    pub fn pattern(&self) -> String {
        let mut result = String::new();
        for pair in &self.pairs {
            result += &pair.to_string();
        }
        result
    }

    /// Retrieves the raw bytes within the address range of the chromosome.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the raw bytes of the chromosome.
    pub fn normalized(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let mut temp_byte: Option<u8> = None;
        for pair in &self.pairs {
            if let Gene::Value(high) = pair.high {
                if let Some(low) = temp_byte {
                    result.push((low << 4) | high);
                    temp_byte = None;
                } else {
                    temp_byte = Some(high);
                }
            }
            if let Gene::Value(low) = pair.low {
                if let Some(high) = temp_byte {
                    result.push((high << 4) | low);
                    temp_byte = None;
                } else {
                    temp_byte = Some(low);
                }
            }
        }
        result
    }

    /// Extracts the feature vector from the normalized chromosome, if enabled.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the feature vector, or an empty vector if feature extraction is disabled.
    pub fn feature(&self) -> Vec<u8> {
        if !self.config.chromosomes.heuristics.features.enabled { return Vec::<u8>::new(); }
        self.normalized()
            .iter()
            .flat_map(|byte| vec![((byte & 0xf0) >> 4) as u8, (byte & 0x0f) as u8])
            .collect()
    }

    /// Computes the TLSH (Locality Sensitive Hash) of the normalized chromosome, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the TLSH, or `None` if TLSH is disabled.
    pub fn tlsh(&self) -> Option<String> {
        if !self.config.chromosomes.hashing.tlsh.enabled { return None; }
        return TLSH::new(&self.normalized(), self.config.chromosomes.hashing.tlsh.minimum_byte_size).hexdigest();
    }

    /// Computes the MinHash of the normalized signature, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the MinHash, or `None` if MinHash is disabled.
    #[allow(dead_code)]
    pub fn minhash(&self) -> Option<String> {
        if !self.config.chromosomes.hashing.minhash.enabled { return None; }
        if self.normalized().len() > self.config.chromosomes.hashing.minhash.maximum_byte_size { return None; }
        return MinHash32::new(
            &self.normalized(),
            self.config.chromosomes.hashing.minhash.number_of_hashes,
            self.config.chromosomes.hashing.minhash.shingle_size,
            self.config.chromosomes.hashing.minhash.seed).hexdigest();
    }

    /// Computes the SHA-256 hash of the normalized chromosome, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the SHA-256 hash, or `None` if SHA-256 is disabled.
    pub fn sha256(&self) -> Option<String> {
        if !self.config.chromosomes.hashing.sha256.enabled { return None; }
        SHA256::new(&self.normalized()).hexdigest()
    }

    /// Computes the entropy of the normalized chromosome, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(f64)` containing the entropy, or `None` if entropy calculation is disabled.
    pub fn entropy(&self) -> Option<f64> {
        if !self.config.chromosomes.heuristics.entropy.enabled { return None; }
        Binary::entropy(&self.normalized())
    }

    /// Processes the chromosome into its JSON-serializable representation.
    ///
    /// # Returns
    ///
    /// Returns a `ChromosomeJson` struct containing metadata about the chromosome.
    pub fn process(&self) -> ChromosomeJson {
        ChromosomeJson {
            pattern: self.pattern(),
            feature: self.feature(),
            sha256: self.sha256(),
            entropy: self.entropy(),
            minhash: self.minhash(),
            tlsh: self.tlsh(),
        }
    }

    /// Converts the signature metadata into a JSON string representation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation of the signature,
    /// or an `Err` if serialization fails.
    #[allow(dead_code)]
    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result =  serde_json::to_string(&raw)?;
        Ok(result)
    }

}
