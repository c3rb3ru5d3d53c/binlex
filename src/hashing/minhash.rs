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
