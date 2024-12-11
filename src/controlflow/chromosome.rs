//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

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
