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

use std::collections::HashMap;
use std::fmt::Write;

/// A struct representing a binary, used for various binary-related utilities.
pub struct Binary;

impl Binary {
    /// Calculates the entropy of the given byte slice.
    ///
    /// This method computes the Shannon entropy, which is a measure of the randomness
    /// or unpredictability of the data. The entropy value is returned as an `Option<f64>`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A reference to a `Vec<u8>` containing the binary data.
    ///
    /// # Returns
    ///
    /// An `Option<f64>`, where `Some(f64)` is the calculated entropy, or `None` if the data
    /// is empty.
    pub fn entropy(bytes: &Vec<u8>) -> Option<f64> {
        let mut frequency: HashMap<u8, usize> = HashMap::new();
        for &byte in bytes {
            *frequency.entry(byte).or_insert(0) += 1;
        }

        let data_len = bytes.len() as f64;
        if data_len == 0.0 {
            return None;
        }

        let entropy = frequency.values().fold(0.0, |entropy, &count| {
            let probability = count as f64 / data_len;
            entropy - probability * probability.log2()
        });

        Some(entropy)
    }

    /// Converts a byte slice to a hexadecimal string representation.
    ///
    /// This method takes a slice of bytes and returns a `String` where each byte is
    /// represented as a 2-character hexadecimal string.
    ///
    /// # Arguments
    ///
    /// * `data` - A reference to a byte slice (`&[u8]`).
    ///
    /// # Returns
    ///
    /// A `String` containing the hexadecimal representation of the byte data.
    pub fn to_hex(data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for byte in data {
            write!(result, "{:02x}", byte).unwrap();
        }
        result
    }

    pub fn from_hex(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("hex string has an odd length".to_string());
        }

        hex.as_bytes()
            .chunks(2)
            .map(|chunk| {
                let hex_str =
                    std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string")?;
                u8::from_str_radix(hex_str, 16).map_err(|_| format!("invalid hex: {}", hex_str))
            })
            .collect()
    }

    /// Creates a human-readable hex dump of the provided byte data.
    ///
    /// This method formats the binary data into a string representation with both
    /// hexadecimal values and ASCII characters, often used for debugging or inspecting
    /// binary content.
    ///
    /// # Arguments
    ///
    /// * `data` - A reference to a byte slice (`&[u8]`).
    /// * `address` - The starting memory address (in hexadecimal) to be used in the dump.
    ///
    /// # Returns
    ///
    /// A `String` formatted as a hex dump with both hexadecimal and ASCII views of the data.
    #[allow(dead_code)]
    pub fn hexdump(data: &[u8], address: u64) -> String {
        const BYTES_PER_LINE: usize = 16;
        let mut result = String::new();
        for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
            let current_address = address as usize + i * BYTES_PER_LINE;
            let hex_repr = format!("{:08x}: ", current_address);
            result.push_str(&hex_repr);
            let hex_values = {
                let mut s = String::new();
                for byte in chunk {
                    let _ = write!(s, "{:02x} ", byte);
                }
                s
            };
            //let hex_values: String = chunk.iter().map(|byte| format!("{:02x} ", byte)).collect();
            result.push_str(&hex_values);
            let padding = "   ".repeat(BYTES_PER_LINE - chunk.len());
            result.push_str(&padding);
            let ascii_values: String = chunk
                .iter()
                .map(|&byte| {
                    if byte.is_ascii_graphic() || byte == b' ' {
                        byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            result.push('|');
            result.push_str(&ascii_values);
            result.push_str("|\n");
        }
        result
    }
}
