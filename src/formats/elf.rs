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

use crate::controlflow::Symbol as BlSymbol;
use crate::formats::File;
use crate::types::MemoryMappedFile;
use crate::Architecture;
use crate::Config;
use lief::elf::section::Flags;
use lief::elf::segment::Type as SegmentType;
use lief::elf::symbol::Type as ElfSymbolType;
use lief::generic::{Section, Symbol};
use lief::Binary;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::{Cursor, Error, ErrorKind};
use std::path::PathBuf;

pub const DEFAULT_IMAGEBASE: u64 = 0x100000;

pub struct ELF {
    elf: lief::elf::Binary,
    pub file: File,
    pub config: Config,
}

impl ELF {
    /// Creates a new `ELF` instance by reading a ELF file from the provided path.
    ///
    /// # Parameters
    /// - `path`: The file path to the ELF file to be loaded.
    ///
    /// # Returns
    /// A `Result` containing the `ELF` object on success or an `Error` on failure.
    pub fn new(path: String, config: Config) -> Result<Self, Error> {
        let mut file = File::new(path.clone(), config.clone())?;
        match file.read() {
            Ok(_) => (),
            Err(_) => {
                return Err(Error::new(ErrorKind::InvalidInput, "failed to read file"));
            }
        };
        let binary = Binary::parse(&path);
        if let Some(Binary::ELF(elf)) = binary {
            return Ok(Self { elf, file, config });
        }
        Err(Error::new(ErrorKind::InvalidInput, "invalid elf file"))
    }

    /// Creates a new `ELF` instance from a byte vector containing ELF file data.
    ///
    /// # Parameters
    /// - `bytes`: A vector of bytes representing the PE file data.
    ///
    /// # Returns
    /// A `Result` containing the `ELF` object on success or an `Error` on failure.
    #[allow(dead_code)]
    pub fn from_bytes(bytes: Vec<u8>, config: Config) -> Result<Self, Error> {
        let file = File::from_bytes(bytes, config.clone());
        let mut cursor = Cursor::new(&file.data);
        if let Some(Binary::ELF(elf)) = Binary::from(&mut cursor) {
            return Ok(Self { elf, file, config });
        }
        Err(Error::new(ErrorKind::InvalidInput, "invalid elf file"))
    }

    pub fn architecture(&self) -> Architecture {
        let architecture = match self.elf.header().machine_type() {
            62 => Architecture::AMD64,
            3 => Architecture::I386,
            _ => Architecture::UNKNOWN,
        };
        architecture
    }

    pub fn entrypoint_virtual_address(&self) -> u64 {
        self.imagebase() + self.elf.header().entrypoint()
    }

    pub fn imagebase(&self) -> u64 {
        for segment in self.elf.segments() {
            if segment.p_type() == SegmentType::LOAD {
                if segment.virtual_address() != 0 {
                    return segment.virtual_address();
                }
                return DEFAULT_IMAGEBASE;
            }
        }
        DEFAULT_IMAGEBASE
    }

    pub fn size(&self) -> u64 {
        self.file.size()
    }

    pub fn export_virtual_addresses(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        for symbol in self.elf.exported_symbols() {
            result.insert(self.imagebase() + symbol.value());
        }
        result
    }

    pub fn symbols(&self) -> BTreeMap<u64, BlSymbol> {
        self.elf
            .dynamic_symbols()
            .chain(self.elf.exported_symbols())
            .chain(self.elf.imported_symbols())
            .chain(self.elf.symtab_symbols())
            .filter(|symbol| symbol.get_type() == ElfSymbolType::FUNC)
            .map(|symbol| {
                (
                    (self.imagebase() + symbol.value()),
                    BlSymbol {
                        symbol_type: "function".to_string(),
                        name: symbol.name(),
                        address: self.imagebase() + symbol.value(),
                    },
                )
            })
            .collect()
    }

    pub fn relative_virtual_address_to_virtual_address(
        &self,
        relative_virtual_address: u64,
    ) -> u64 {
        self.imagebase() + relative_virtual_address
    }

    pub fn file_offset_to_virtual_address(&self, file_offset: u64) -> Option<u64> {
        for segment in self.elf.segments() {
            let start = segment.file_offset();
            let end = start + segment.physical_size();
            if file_offset >= start && file_offset < end {
                let segment_virtual_address = self.imagebase() + segment.virtual_address();
                return Some(segment_virtual_address + (file_offset - start));
            }
        }
        None
    }

    pub fn image(&self) -> Result<MemoryMappedFile, Error> {
        let pathbuf = PathBuf::from(self.config.mmap.directory.clone())
            .join(self.file.sha256_no_config().unwrap());
        let mut tempmap = MemoryMappedFile::new(pathbuf, self.config.mmap.cache.enabled)?;

        if tempmap.is_cached() {
            return Ok(tempmap);
        }

        tempmap.seek_to_end()?;
        tempmap.write(&self.file.data[0..self.elf.header().header_size() as usize])?;

        for segment in self.elf.segments() {
            let segment_virtual_address = self.imagebase() + segment.virtual_address();

            if segment_virtual_address > tempmap.size()? {
                let padding_length = segment_virtual_address - tempmap.size()?;
                tempmap.seek_to_end()?;
                tempmap.write_padding(padding_length as usize)?;
            }

            if segment.p_type() == SegmentType::LOAD {
                let segment_file_offset = segment.file_offset() as usize;
                let segment_size = segment.physical_size() as usize;

                if segment_file_offset + segment_size <= self.file.data.len() {
                    tempmap.seek_to_end()?;
                    tempmap.write(
                        &self.file.data[segment_file_offset..segment_file_offset + segment_size],
                    )?;
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "elf segment size exceeds file data length",
                    ));
                }
            }
        }

        Ok(tempmap)
    }

    pub fn tlsh(&self) -> Option<String> {
        self.file.tlsh()
    }

    pub fn sha256(&self) -> Option<String> {
        self.file.sha256()
    }

    /// Returns the entropy of the ELF file.
    ///
    /// # Returns
    /// The entropy of the file as a `Option<f64>`.
    #[allow(dead_code)]
    pub fn entropy(&self) -> Option<f64> {
        self.file.entropy()
    }

    /// Returns the File JSON associated with the ELF
    ///
    /// # Returns
    /// An `Result<String, Error>` containing the `File` JSON.
    #[allow(dead_code)]
    pub fn file_json(&self) -> Result<String, Error> {
        self.file.json()
    }

    pub fn entrypoint_virtual_addresses(&self) -> BTreeSet<u64> {
        let mut entrypoints = BTreeSet::<u64>::new();
        entrypoints.insert(self.entrypoint_virtual_address());
        entrypoints.extend(self.export_virtual_addresses());
        entrypoints.extend(self.symbols().keys());
        entrypoints
    }

    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        for section in self.elf.sections() {
            if section.flags().contains(Flags::EXECINSTR) {
                let start = self.imagebase() + section.virtual_address();
                let end = start + section.size();
                result.insert(start, end);
            }
        }
        result
    }
}
