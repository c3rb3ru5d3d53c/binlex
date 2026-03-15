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

use crate::Config;
use crate::entropy;
use crate::genetics::AllelePair;
use crate::genetics::Gene;
use crate::hashing::MinHash32;
use crate::hashing::SHA256;
use crate::hashing::TLSH;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::Error;
use std::io::ErrorKind;

/// Represents a JSON-serializable structure containing metadata about a chromosome.
#[derive(Serialize, Deserialize, Clone)]
pub struct ChromosomeJson {
    /// The raw pattern string of the chromosome.
    pub pattern: String,
    /// The feature vector extracted from the chromosome.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub feature: Vec<u8>,
    /// The entropy of the normalized chromosome, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// The SHA-256 hash of the normalized chromosome, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The MinHash of the normalized chromosome, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minhash: Option<String>,
    /// The TLSH (Locality Sensitive Hash) of the normalized chromosome, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
}

/// Represents a chromosome within a control flow graph.
#[derive(Clone)]
pub struct Chromosome {
    pub allelepairs: Vec<AllelePair>,
    pub number_of_mutations: usize,
    config: Config,
}

impl Chromosome {
    /// Creates a new `Chromosome` instance for a specified address range within a control flow graph.
    ///
    /// # Returns
    ///
    /// Returns `Result<Chromosome, Error>`.
    pub fn new(pattern: String, config: Config) -> Result<Self, Error> {
        let allelepairs = Self::parse_pairs(pattern)?;
        Ok(Self {
            allelepairs,
            number_of_mutations: 0,
            config,
        })
    }

    pub fn number_of_mutations(&self) -> usize {
        self.number_of_mutations
    }

    pub fn mutate(&mut self, pattern: String) -> Result<(), Error> {
        self.allelepairs = Self::parse_pairs(pattern)?;
        self.number_of_mutations += 1;
        Ok(())
    }

    #[allow(dead_code)]
    fn parse_pairs(pattern: String) -> Result<Vec<AllelePair>, Error> {
        if pattern.len() % 2 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "pattern length must be even",
            ));
        }
        let mut parsed = Vec::new();
        let chars: Vec<char> = pattern.chars().collect();
        for chunk in chars.chunks(2) {
            let high = Self::parse_gene(chunk[0])?;
            let low = Self::parse_gene(chunk[1])?;
            parsed.push(AllelePair {
                high,
                low,
                number_mutations: 0,
            });
        }
        Ok(parsed)
    }

    fn parse_gene(c: char) -> Result<Gene, Error> {
        Gene::from_char(c)
    }

    pub fn allelepairs(&self) -> Vec<AllelePair> {
        self.allelepairs.clone()
    }

    pub fn pattern(&self) -> String {
        let mut result = String::new();
        for pair in &self.allelepairs {
            result += &pair.to_string();
        }
        result
    }

    /// Retrieves the raw bytes within the address range of the chromosome.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the normalized bytes of the chromosome.
    pub fn normalized(&self) -> Vec<u8> {
        let mut result = Vec::new();
        let mut temp_byte: Option<u8> = None;
        for pair in &self.allelepairs {
            if let Some(high) = pair.high.value() {
                if let Some(low) = temp_byte {
                    result.push((low << 4) | high);
                    temp_byte = None;
                } else {
                    temp_byte = Some(high);
                }
            }
            if let Some(low) = pair.low.value() {
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
        let mut result = Vec::<u8>::new();
        if !self.config.chromosomes.features.enabled {
            return result;
        }
        for allelepair in &self.allelepairs {
            if let Some(high) = allelepair.high.value() {
                result.push(high);
            }
            if let Some(low) = allelepair.low.value() {
                result.push(low);
            }
        }
        result
    }

    /// Computes the TLSH (Locality Sensitive Hash) of the normalized chromosome, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the TLSH, or `None` if TLSH is disabled.
    pub fn tlsh(&self) -> Option<String> {
        if !self.config.chromosomes.hashing.tlsh.enabled {
            return None;
        }
        TLSH::new(
            &self.normalized(),
            self.config.chromosomes.hashing.tlsh.minimum_byte_size,
        )
        .hexdigest()
    }

    /// Computes the MinHash of the normalized signature, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the MinHash, or `None` if MinHash is disabled.
    #[allow(dead_code)]
    pub fn minhash(&self) -> Option<String> {
        if !self.config.chromosomes.hashing.minhash.enabled {
            return None;
        }
        if self.normalized().len() > self.config.chromosomes.hashing.minhash.maximum_byte_size
            && self
                .config
                .chromosomes
                .hashing
                .minhash
                .maximum_byte_size_enabled
        {
            return None;
        }
        MinHash32::new(
            &self.normalized(),
            self.config.chromosomes.hashing.minhash.number_of_hashes,
            self.config.chromosomes.hashing.minhash.shingle_size,
            self.config.chromosomes.hashing.minhash.seed,
        )
        .hexdigest()
    }

    /// Computes the SHA-256 hash of the normalized chromosome, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the SHA-256 hash, or `None` if SHA-256 is disabled.
    pub fn sha256(&self) -> Option<String> {
        if !self.config.chromosomes.hashing.sha256.enabled {
            return None;
        }
        SHA256::new(&self.normalized()).hexdigest()
    }

    /// Computes the entropy of the normalized chromosome, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(f64)` containing the entropy, or `None` if entropy calculation is disabled.
    pub fn entropy(&self) -> Option<f64> {
        if !self.config.chromosomes.entropy.enabled {
            return None;
        }
        entropy::shannon(&self.normalized())
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
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Prints the JSON representation of the chromosome to standard output.
    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }
}
