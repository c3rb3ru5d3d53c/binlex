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

use lief::generic::{Section, Symbol};
use lief::Binary;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Error, ErrorKind};
use crate::Architecture;
use crate::formats::File;
use crate::Config;
use lief::macho::header::CpuType as MachoCpuType;
use crate::controlflow::Symbol as BlSymbol;
use crate::types::MemoryMappedFile;
use std::path::PathBuf;
use lief::macho::commands::{Command, LoadCommandTypes};
use lief::macho::section::Flags as SectionFlags;

pub const N_STAB: u8 = 0xE0;
pub const N_TYPE: u8 = 0x0E;
pub const N_SECT: u8 = 0x0E;
pub const VM_PROT_EXECUTE: u8 = 0x04;

pub struct MACHO {
    macho: lief::macho::FatBinary,
    pub file: File,
    pub config: Config,
}

impl MACHO {
    /// Creates a new `MACHO` instance by reading a ELF file from the provided path.
    ///
    /// # Parameters
    /// - `path`: The file path to the MACHO file to be loaded.
    ///
    /// # Returns
    /// A `Result` containing the `MACHO` object on success or an `Error` on failure.
    pub fn new(path: String, config: Config) -> Result<Self, Error> {
        let mut file = File::new(path.clone(), config.clone())?;
        match file.read() {
            Ok(_) => (),
            Err(_) => {
                return Err(Error::new(ErrorKind::InvalidInput, "failed to read macho file"));
            }
        };
        let binary = Binary::parse(&path);
        if let Some(Binary::MachO(macho)) = binary {
            return Ok(Self {
                macho: macho,
                file: file,
                config: config,
            });
        }
        return Err(Error::new(ErrorKind::InvalidInput, "invalid macho file"));
    }

    /// Creates a new `MACHO` instance from a byte vector containing MACHO file data.
    ///
    /// # Parameters
    /// - `bytes`: A vector of bytes representing the PE file data.
    ///
    /// # Returns
    /// A `Result` containing the `MACHO` object on success or an `Error` on failure.
    #[allow(dead_code)]
    pub fn from_bytes(bytes: Vec<u8>, config: Config) -> Result<Self, Error> {
        let file = File::from_bytes(bytes, config.clone());
        let mut cursor = Cursor::new(&file.data);
        if let Some(Binary::MachO(macho)) = Binary::from(&mut cursor) {
            return Ok(Self{
                macho: macho,
                file: file,
                config: config,
            })
        }
        return Err(Error::new(ErrorKind::InvalidInput, "invalid macho file"));
    }

    pub fn relative_virtual_address_to_virtual_address(&self, relative_virtual_address: u64, slice: usize) -> Option<u64> {
        Some(self.imagebase(slice)? + relative_virtual_address)
    }

    pub fn file_offset_to_virtual_address(&self, file_offset: u64, slice: usize) -> Option<u64> {
        let binding = self.macho.iter().nth(slice);
        if binding.is_none() { return None; }
        for segment in binding.unwrap().segments() {
            let start = segment.file_offset();
            let end = start + segment.file_size();
            if file_offset >= start && file_offset < end {
                return Some(segment.virtual_address() + (file_offset - start));
            }
        }
        None
    }

    /// Returns the number of binaries contained in the MachO binary.
    ///
    /// # Returns
    /// A `usize` containing the number of binaries in the MachO binary.
    pub fn number_of_slices(&self) -> usize {
        self.macho.iter().count()
    }

    /// Returns the entrypoint of the MachO binary by index.
    ///
    /// # Returns
    /// A `Option<u64>` representing the entrypoint of the binary.
    pub fn entrypoint_virtual_address(&self, slice: usize) -> Option<u64> {
        Some(self.imagebase(slice)? + self.macho.iter().nth(slice)?.main_command()?.entrypoint())
    }

    /// Returns the imagebase of the MachO binary by index.
    ///
    /// # Returns
    /// A `Option<u64>` representing the imagebase of the binary.
    pub fn imagebase(&self, slice: usize) -> Option<u64> {
        let binding = self.macho.iter().nth(slice)?;
        for segment in binding.segments() {
            if segment.name() == "__TEXT" {
                return Some(segment.virtual_address())
            }
        }
        Some(0)
    }

    /// Returns the size of the headers for the MachO slice.
    ///
    /// # Returns
    /// A `Option<u64>` representing the size of the headers for the MachO slice.
    pub fn sizeofheaders(&self, slice: usize) -> Option<u64> {
        let binding = self.macho.iter().nth(slice)?;
        let architecture = self.architecture(slice)?;
        let macho_header_size: u32 = match architecture {
            Architecture::AMD64 => 32,
            Architecture::I386 => 28,
            _ => { return None; }
        };
        Some(macho_header_size as u64 + binding.header().sizeof_cmds() as u64)
    }

    /// Returns the architecture of the MachO binary by index.
    ///
    /// # Returns
    /// A `Option<Architecture>` representing the architecture of the binary.
    pub fn architecture(&self, slice: usize) -> Option<Architecture> {
        let cpu_type = self.macho.iter().nth(slice).map(|b|b.header().cpu_type());
        if cpu_type.is_none() { return None; }
        let architecture = match cpu_type.unwrap() {
            MachoCpuType::X86 => Architecture::I386,
            MachoCpuType::X86_64 => Architecture::AMD64,
            _ => { return None; },
        };
        Some(architecture)
    }

    /// Checks if the symbol n_type is a function.
    ///
    /// # Returns
    /// A `bool` representing if the n_type is a function or not.
    pub fn is_function_symbol_type(n_type: u8) -> bool {
        (n_type & N_STAB) == 0 && (n_type & N_TYPE) == N_SECT
    }

    pub fn symbols(&self, slice: usize) -> BTreeMap<u64, BlSymbol> {
        let mut symbols = BTreeMap::<u64, BlSymbol>::new();
        let binding = self.macho.iter().nth(slice);
        if binding.is_none() { return symbols; }
        for symbol in binding.unwrap().symbols() {
            if !MACHO::is_function_symbol_type(symbol.get_type()) { continue; }
            symbols.insert(symbol.value(), BlSymbol{
                symbol_type: "function".to_string(),
                name: symbol.name(),
                address: symbol.value(),
            });
        }
        symbols
    }

    /// Returns a set of function addresses identified in the MachO slice.
    ///
    /// # Returns
    /// A `BTreeSet` of function addresses for the MachO slice.
    pub fn entrypoint_virtual_addresses(&self, slice: usize) -> BTreeSet<u64> {
        let mut entrypoints = BTreeSet::<u64>::new();
        if self.entrypoint_virtual_address(slice).is_some() {
            entrypoints.insert(self.entrypoint_virtual_address(slice).unwrap());
        }
        entrypoints.extend(self.symbols(slice).keys());
        entrypoints.extend(self.export_virtual_addresses(slice));
        entrypoints
    }

    /// Checks if the provided segment flags contain the executable flag.
    ///
    /// # Arguments
    ///
    /// `segment_flags` The segment flags as a `u32`
    ///
    /// # Returns
    /// A `bool` representing if the segment flags contain the executable flag or not.
    pub fn is_segment_flags_executable(segment_flags: u32) -> bool {
        (segment_flags & VM_PROT_EXECUTE as u32) != 0
    }

    /// Checks if the symbol n_type is a function.
    ///
    /// # Arguments
    ///
    /// `slice` The index representing a binary contained in the MacO fat binary format.
    ///
    /// # Returns
    /// A `BTreeSet<u64>` containing the virtual addresses of function export addresses.
    pub fn export_virtual_addresses(&self, slice: usize) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        let binding = self.macho.iter().nth(slice);
        if binding.is_none() { return result; }
        let binding = binding.unwrap();
        let dyld_exports_trie = binding.dyld_exports_trie();
        if dyld_exports_trie.is_none() { return result; }
        for export in dyld_exports_trie.unwrap().exports() {
            result.insert(self.imagebase(slice).unwrap() + export.address());
        }
        result
    }

    pub fn executable_virtual_address_ranges(&self, slice: usize) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        let binding = self.macho.iter().nth(slice);
        if binding.is_none() { return result; }
        for segment in binding.unwrap().segments() {
            if !MACHO::is_segment_flags_executable(segment.init_protection()) { continue; }
            for section in segment.sections() {
                if [
                    "__cstring",
                    "__const",
                    "__info_plist",
                    "__unwind_info",
                    "__eh_frame",
                    "__stubs",
                    "__stub_helper"].contains(&section.name().as_str()) { continue; }
                if !section.flags().contains(SectionFlags::PURE_INSTRUCTIONS) { continue; }
                if !section.flags().contains(SectionFlags::SOME_INSTRUCTIONS) { continue; }
                let start = section.virtual_address();
                let end = start + section.size();
                result.insert(start, end);
            }
        }
        result
    }

    /// Caches the MachO file contents and returns a `MemoryMappedFile` object.
    ///
    /// # Parameters
    /// - `slice`: The MachoO binary slice.
    ///
    /// # Returns
    /// A `Result` containing the `MemoryMappedFile` object on success or an `Error` on failure.
    pub fn image(&self, slice: usize) -> Result<MemoryMappedFile, Error> {
        let pathbuf = PathBuf::from(self.config.mmap.directory.clone())
            .join(self.file.sha256_no_config().unwrap());

        let mut tempmap = match MemoryMappedFile::new(
            pathbuf,
            self.config.mmap.cache.enabled) {
            Ok(tempmmap) => tempmmap,
            Err(error) => return Err(error),
        };

        if tempmap.is_cached() {
            return Ok(tempmap);
        }

        let sizeofheaders = self.sizeofheaders(slice);
        tempmap.seek_to_end()?;
        tempmap.write(&self.file.data[0..sizeofheaders.unwrap() as usize])?;

        let binary = match self.macho.iter().nth(slice) {
            Some(binary) => binary,
            None => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid Mach-O slice",
                ));
            }
        };

        for segment in binary.segments() {
            let segment_virtual_address = segment.virtual_address();
            if segment_virtual_address > tempmap.size()? as u64 {
                let padding_length = segment_virtual_address - tempmap.size()? as u64;
                tempmap.seek_to_end()?;
                tempmap.write_padding(padding_length as usize)?;
            }
            if !matches!(segment.command_type(), LoadCommandTypes::Segment | LoadCommandTypes::Segment64) { continue; }
            let segment_file_offset = segment.file_offset() as usize;
            let segment_size = segment.file_size() as usize;
            if segment_file_offset + segment_size <= self.file.data.len() {
                tempmap.seek_to_end()?;
                tempmap.write(&self.file.data[segment_file_offset..segment_file_offset + segment_size])?;
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "macho slice segment size exceeds file data length",
                ));
            }
        }

        Ok(tempmap)
    }

}
