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

use crate::controlflow::Attribute;
use crate::hashing::sha256::SHA256;
use crate::hashing::tlsh::TLSH;
use crate::Binary;
use crate::Config;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File as StdFile;
use std::io::ErrorKind;
use std::io::{Cursor, Error, Read, Seek, SeekFrom};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

#[cfg(windows)]
use std::fs::OpenOptions;

#[cfg(windows)]
use winapi::um::winnt::FILE_SHARE_READ;

pub trait FileHandle: Read + Seek + Send {}

impl<T: Read + Seek + Send> FileHandle for T {}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileJson {
    #[serde(rename = "type")]
    /// The type always `file`
    pub type_: String,
    /// The SHA-256 hash of the file, if available.
    pub sha256: Option<String>,
    /// The TLSH (Trend Micro Locality Sensitive Hash) of the file, if available.
    pub tlsh: Option<String>,
    /// The File Size,
    pub size: Option<u64>,
    // The File Entropy
    pub entropy: Option<f64>,
}

/// Represents a file with its contents and an optional file path.
pub struct File {
    /// The contents of the file as a byte vector.
    pub data: Vec<u8>,
    /// The path of the file, if available.
    pub path: Option<String>,
    /// The configuration `Config`
    pub config: Config,
    /// Handle to the file
    handle: Box<dyn FileHandle>,
}

impl File {
    /// Creates a new `File` instance with a given path.
    ///
    /// # Arguments
    ///
    /// * `path` - A `String` representing the path to the file.
    ///
    /// # Returns
    ///
    /// A `File` instance with the given path and empty data.
    pub fn new(path: String, config: Config) -> Result<Self, Error> {
        #[cfg(windows)]
        let handle = Box::new(
            OpenOptions::new()
                .read(true)
                .write(false)
                .share_mode(FILE_SHARE_READ)
                .open(&path)?,
        ) as Box<dyn FileHandle>;
        #[cfg(not(windows))]
        let handle = Box::new(StdFile::open(&path)?) as Box<dyn FileHandle>;
        Ok(Self {
            data: Vec::new(),
            path: Some(path),
            config,
            handle,
        })
    }

    /// Creates a new `File` instance from the provided byte data.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A `Vec<u8>` representing the byte data of the file.
    ///
    /// # Returns
    ///
    /// A `File` instance with the given byte data and no path.
    #[allow(dead_code)]
    pub fn from_bytes(bytes: Vec<u8>, config: Config) -> Self {
        let handle = Box::new(Cursor::new(bytes.clone())) as Box<dyn FileHandle>;
        Self {
            data: bytes,
            path: None,
            config,
            handle,
        }
    }

    /// Computes the TLSH (Trend Locality Sensitive Hashing) of the file's data.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the hexadecimal representation of the TLSH,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn tlsh(&self) -> Option<String> {
        if !self.config.formats.file.hashing.tlsh.enabled {
            return None;
        }
        if self.size() == 0 {
            return None;
        }
        TLSH::new(&self.data, 50).hexdigest()
    }

    /// Computes the SHA-256 hash of the file's data.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the hexadecimal representation of the SHA-256 hash,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn sha256(&self) -> Option<String> {
        if !self.config.formats.file.hashing.sha256.enabled {
            return None;
        }
        if self.size() == 0 {
            return None;
        }
        SHA256::new(&self.data).hexdigest()
    }

    /// Computes the SHA-256 hash of the file's data.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the hexadecimal representation of the SHA-256 hash,
    /// or `None` if the file's size is zero or less.
    #[allow(dead_code)]
    pub fn sha256_no_config(&self) -> Option<String> {
        if self.size() == 0 {
            return None;
        }
        SHA256::new(&self.data).hexdigest()
    }

    /// Returns the size of the file in bytes.
    ///
    /// # Returns
    ///
    /// The size of the file in bytes as a `u64`.
    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// Seeks to a specific offset in the file.
    ///
    /// # Arguments
    ///
    /// * `offset` - The position to seek to, specified as a `u64` (absolute offset from the start of the file).
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the seek operation, returning the new position.
    ///
    /// # Errors
    ///
    /// Returns an error if the file path is missing or the seek operation fails.
    pub fn seek(&mut self, offset: u64) -> Result<u64, Error> {
        let new_position = self.handle.seek(SeekFrom::Start(offset))?;
        Ok(new_position)
    }

    /// Gets the current position of the file cursor.
    /// # Returns
    ///
    /// A `Result<u64, Error>` with the current cursor position.
    pub fn current_position(&mut self) -> Result<u64, Error> {
        let position = self.handle.stream_position()?;
        Ok(position)
    }

    /// Reads the content of the file from the given path and stores it in `data`.
    ///
    /// # Returns
    ///
    /// A `Result` indicating the success or failure of the operation.
    /// Returns `Ok(())` on success, or an `Err` with an `Error` if the file cannot be read.
    ///
    /// # Errors
    ///
    /// Returns an error if the file path is missing or the file cannot be opened or read.
    pub fn read(&mut self) -> Result<(), Error> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "missing file path to read"))?;

        let mut file = StdFile::open(path)?;
        file.read_to_end(&mut self.data)?;
        Ok(())
    }

    /// Prints the JSON representation of the file metadata to standard output.
    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{json}");
        }
    }

    /// Processes the file metadata into a JSON-serializable `FileJson` structure.
    ///
    /// # Returns
    ///
    /// Returns a `FileJson` struct containing the file's SHA-256 hash, TLSH hash, and size.
    pub fn process(&self) -> FileJson {
        FileJson {
            type_: "file".to_string(),
            sha256: self.sha256(),
            tlsh: self.tlsh(),
            size: Some(self.size()),
            entropy: self.entropy(),
        }
    }

    pub fn entropy(&self) -> Option<f64> {
        if !self.config.formats.file.heuristics.entropy.enabled {
            return None;
        }
        Binary::entropy(&self.data)
    }

    /// Gets attribute information about a file
    ///
    /// # Returns
    ///
    /// Returns a `Attribute` struct containing the file's SHA-256 hash, TLSH hash, and size.
    pub fn attribute(&self) -> Attribute {
        Attribute::File(self.process())
    }

    /// Converts the file metadata into a JSON string representation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation of the file metadata,
    /// or an `Err` if serialization fails.
    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }
}
