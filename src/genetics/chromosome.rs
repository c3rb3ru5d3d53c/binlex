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
use crate::hashing::MinHash32;
use crate::hashing::SHA256;
use crate::hashing::SSDeep;
use crate::hashing::TLSH;
use crate::hex;
use crate::imaging::Imaging;
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::Error;
use std::io::ErrorKind;

/// Represents a JSON-serializable structure containing metadata about a chromosome.
#[derive(Serialize, Deserialize, Clone)]
pub struct ChromosomeJson {
    /// The rendered YARA-compatible pattern of the chromosome.
    pub pattern: String,
    /// Hex-encoded wildcard mask for the chromosome, one byte per source byte.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mask: String,
    /// Hex-encoded masked chromosome bytes with wildcard bits zeroed in place.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub masked: String,
    /// The vector extracted from the chromosome.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vector: Vec<u8>,
    /// The entropy of the masked chromosome bytes, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// The SHA-256 hash of the masked chromosome bytes, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The ssdeep fuzzy hash of the masked chromosome bytes, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<String>,
    /// The MinHash of the masked chromosome bytes, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minhash: Option<String>,
    /// The TLSH (Locality Sensitive Hash) of the masked chromosome bytes, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
}

/// Represents a chromosome within a control flow graph.
#[derive(Clone)]
pub struct Chromosome {
    raw_bytes: Vec<u8>,
    wildcard_mask: Vec<u8>,
    number_of_mutations: usize,
    config: Config,
}

impl Chromosome {
    /// Creates a new chromosome from raw bytes and a per-byte wildcard mask.
    pub fn new(raw_bytes: Vec<u8>, wildcard_mask: Vec<u8>, config: Config) -> Result<Self, Error> {
        Self::validate_lengths(&raw_bytes, &wildcard_mask)?;
        Ok(Self {
            raw_bytes,
            wildcard_mask,
            number_of_mutations: 0,
            config,
        })
    }

    /// Creates a chromosome from a YARA-style pattern. This path is inherently lossy.
    pub fn from_pattern(pattern: String, config: Config) -> Result<Self, Error> {
        let (raw_bytes, wildcard_mask) = Self::parse_pattern(pattern)?;
        Self::new(raw_bytes, wildcard_mask, config)
    }

    fn validate_lengths(raw_bytes: &[u8], wildcard_mask: &[u8]) -> Result<(), Error> {
        if raw_bytes.len() != wildcard_mask.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "raw bytes and wildcard mask must have the same length",
            ));
        }
        Ok(())
    }

    fn parse_pattern(pattern: String) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if pattern.len() % 2 != 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "pattern length must be even",
            ));
        }

        let mut raw_bytes = Vec::with_capacity(pattern.len() / 2);
        let mut wildcard_mask = Vec::with_capacity(pattern.len() / 2);
        let chars: Vec<char> = pattern.chars().collect();

        for chunk in chars.chunks(2) {
            let (high_value, high_mask) = Self::parse_pattern_nibble(chunk[0])?;
            let (low_value, low_mask) = Self::parse_pattern_nibble(chunk[1])?;
            raw_bytes.push((high_value << 4) | low_value);
            wildcard_mask.push((high_mask << 4) | low_mask);
        }

        Ok((raw_bytes, wildcard_mask))
    }

    fn parse_pattern_nibble(c: char) -> Result<(u8, u8), Error> {
        match c {
            '?' => Ok((0, 0xF)),
            '0'..='9' | 'a'..='f' | 'A'..='F' => c
                .to_digit(16)
                .map(|v| (v as u8, 0))
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid hexadecimal digit")),
            _ => Err(Error::new(ErrorKind::InvalidInput, "invalid character")),
        }
    }

    #[allow(dead_code)]
    fn render_nibble(value: u8, mask: u8) -> char {
        if mask != 0 {
            '?'
        } else {
            char::from_digit(value as u32, 16).expect("valid nibble")
        }
    }

    pub fn mutations(&self) -> usize {
        self.number_of_mutations
    }

    pub fn mutate(&mut self, raw_bytes: Vec<u8>, wildcard_mask: Vec<u8>) -> Result<(), Error> {
        Self::validate_lengths(&raw_bytes, &wildcard_mask)?;
        self.raw_bytes = raw_bytes;
        self.wildcard_mask = wildcard_mask;
        self.number_of_mutations += 1;
        Ok(())
    }

    pub fn mutate_pattern(&mut self, pattern: String) -> Result<(), Error> {
        let (raw_bytes, wildcard_mask) = Self::parse_pattern(pattern)?;
        self.mutate(raw_bytes, wildcard_mask)
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.raw_bytes.clone()
    }

    pub fn mask(&self) -> Vec<u8> {
        self.wildcard_mask.clone()
    }

    pub fn allelepairs(&self) -> Vec<AllelePair> {
        let pattern = self.pattern();
        let mut result = Vec::with_capacity(pattern.len() / 2);
        let chars: Vec<char> = pattern.chars().collect();
        for chunk in chars.chunks(2) {
            let pair = chunk.iter().collect::<String>();
            result.push(AllelePair::from_string(pair).expect("rendered chromosome pair is valid"));
        }
        result
    }

    pub fn pattern(&self) -> String {
        let mut result = String::with_capacity(self.raw_bytes.len() * 2);
        for (&value, &mask) in self.raw_bytes.iter().zip(&self.wildcard_mask) {
            result.push(Self::render_nibble((value >> 4) & 0xF, (mask >> 4) & 0xF));
            result.push(Self::render_nibble(value & 0xF, mask & 0xF));
        }
        result
    }

    /// Returns the masked bytes produced by applying the wildcard mask in place.
    pub fn masked(&self) -> Vec<u8> {
        self.raw_bytes
            .iter()
            .zip(&self.wildcard_mask)
            .map(|(&value, &mask)| value & !mask)
            .collect()
    }

    /// Returns an imaging pipeline for the masked chromosome bytes.
    pub fn imaging(&self) -> Imaging {
        Imaging::new(self.masked(), self.config.clone())
    }

    /// Extracts the nibble vector from the masked chromosome bytes.
    pub fn vector(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.raw_bytes.len() * 2);
        for value in self.masked() {
            result.push((value >> 4) & 0xF);
            result.push(value & 0xF);
        }
        result
    }

    /// Computes the TLSH (Locality Sensitive Hash) of the masked chromosome.
    pub fn tlsh(&self) -> Option<TLSH<'static>> {
        Some(TLSH::from_bytes(
            self.masked(),
            self.config.chromosomes.tlsh.minimum_byte_size,
        ))
    }

    /// Computes the MinHash of the masked chromosome bytes.
    #[allow(dead_code)]
    pub fn minhash(&self) -> Option<MinHash32<'static>> {
        let masked = self.masked();
        if masked.len() > self.config.chromosomes.minhash.maximum_byte_size
            && self.config.chromosomes.minhash.maximum_byte_size_enabled
        {
            return None;
        }
        Some(MinHash32::from_bytes(
            masked,
            self.config.chromosomes.minhash.number_of_hashes,
            self.config.chromosomes.minhash.shingle_size,
            self.config.chromosomes.minhash.seed,
        ))
    }

    /// Computes the SHA-256 hash of the masked chromosome bytes.
    pub fn sha256(&self) -> Option<SHA256<'static>> {
        Some(SHA256::from_bytes(self.masked()))
    }

    /// Computes the ssdeep hash of the masked chromosome bytes.
    pub fn ssdeep(&self) -> Option<SSDeep<'static>> {
        Some(SSDeep::from_bytes(self.masked()))
    }

    /// Computes the entropy of the masked chromosome bytes.
    pub fn entropy(&self) -> Option<f64> {
        entropy::shannon(&self.masked())
    }

    /// Processes the chromosome into its JSON-serializable representation.
    pub fn process(&self) -> ChromosomeJson {
        ChromosomeJson {
            pattern: self.pattern(),
            mask: if self.config.chromosomes.mask.enabled {
                hex::encode(&self.mask())
            } else {
                String::new()
            },
            masked: if self.config.chromosomes.masked.enabled {
                hex::encode(&self.masked())
            } else {
                String::new()
            },
            vector: if self.config.chromosomes.vector.enabled {
                self.vector()
            } else {
                Vec::new()
            },
            sha256: if self.config.chromosomes.sha256.enabled {
                self.sha256().and_then(|hash| hash.hexdigest())
            } else {
                None
            },
            ssdeep: if self.config.chromosomes.ssdeep.enabled {
                self.ssdeep().and_then(|hash| hash.hexdigest())
            } else {
                None
            },
            entropy: if self.config.chromosomes.entropy.enabled {
                self.entropy()
            } else {
                None
            },
            minhash: if self.config.chromosomes.minhash.enabled {
                self.minhash().and_then(|hash| hash.hexdigest())
            } else {
                None
            },
            tlsh: if self.config.chromosomes.tlsh.enabled {
                self.tlsh().and_then(|hash| hash.hexdigest())
            } else {
                None
            },
        }
    }

    /// Converts the signature metadata into a JSON string representation.
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
