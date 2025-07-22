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

use crate::controlflow::Symbol as BlSymbol;
use crate::formats::File;
use crate::types::MemoryMappedFile;
use crate::Architecture;
use crate::Config;
use lief::generic::{Section, Symbol};
use lief::macho::commands::{Command, LoadCommandTypes};
use lief::macho::header::CpuType as MachoCpuType;
use lief::macho::section::Flags as SectionFlags;
use lief::Binary;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Error, ErrorKind};
use std::path::PathBuf;

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
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "failed to read macho file",
                ));
            }
        };
        let binary = Binary::parse(&path);
        if let Some(Binary::MachO(macho)) = binary {
            return Ok(Self {
                macho,
                file,
                config,
            });
        }
        Err(Error::new(ErrorKind::InvalidInput, "invalid macho file"))
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
            return Ok(Self {
                macho,
                file,
                config,
            });
        }
        Err(Error::new(ErrorKind::InvalidInput, "invalid macho file"))
    }

    pub fn relative_virtual_address_to_virtual_address(
        &self,
        relative_virtual_address: u64,
        slice: usize,
    ) -> Option<u64> {
        Some(self.imagebase(slice)? + relative_virtual_address)
    }

    pub fn file_offset_to_virtual_address(&self, file_offset: u64, slice: usize) -> Option<u64> {
        let binding = self.macho.iter().nth(slice);
        binding.as_ref()?;
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
                return Some(segment.virtual_address());
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
            _ => {
                return None;
            }
        };
        Some(macho_header_size as u64 + binding.header().sizeof_cmds() as u64)
    }

    /// Returns the architecture of the MachO binary by index.
    ///
    /// # Returns
    /// A `Option<Architecture>` representing the architecture of the binary.
    pub fn architecture(&self, slice: usize) -> Option<Architecture> {
        let cpu_type = self.macho.iter().nth(slice).map(|b| b.header().cpu_type());
        cpu_type.as_ref()?;
        let architecture = match cpu_type.unwrap() {
            MachoCpuType::X86 => Architecture::I386,
            MachoCpuType::X86_64 => Architecture::AMD64,
            _ => {
                return None;
            }
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
        if binding.is_none() {
            return symbols;
        }
        for symbol in binding.unwrap().symbols() {
            if !MACHO::is_function_symbol_type(symbol.get_type()) {
                continue;
            }
            symbols.insert(
                symbol.value(),
                BlSymbol {
                    symbol_type: "function".to_string(),
                    name: symbol.name(),
                    address: symbol.value(),
                },
            );
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
        if binding.is_none() {
            return result;
        }
        let binding = binding.unwrap();
        let dyld_exports_trie = binding.dyld_exports_trie();
        if dyld_exports_trie.is_none() {
            return result;
        }
        for export in dyld_exports_trie.unwrap().exports() {
            result.insert(self.imagebase(slice).unwrap() + export.address());
        }
        result
    }

    pub fn executable_virtual_address_ranges(&self, slice: usize) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        let binding = self.macho.iter().nth(slice);
        if binding.is_none() {
            return result;
        }
        for segment in binding.unwrap().segments() {
            if !MACHO::is_segment_flags_executable(segment.init_protection()) {
                continue;
            }
            for section in segment.sections() {
                if [
                    "__cstring",
                    "__const",
                    "__info_plist",
                    "__unwind_info",
                    "__eh_frame",
                    "__stubs",
                    "__stub_helper",
                ]
                .contains(&section.name().as_str())
                {
                    continue;
                }
                if !section.flags().contains(SectionFlags::PURE_INSTRUCTIONS) {
                    continue;
                }
                if !section.flags().contains(SectionFlags::SOME_INSTRUCTIONS) {
                    continue;
                }
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

        let mut tempmap = MemoryMappedFile::new(pathbuf, self.config.mmap.cache.enabled)?;

        if tempmap.is_cached() {
            return Ok(tempmap);
        }

        let sizeofheaders = self.sizeofheaders(slice);
        tempmap.seek_to_end()?;
        tempmap.write(&self.file.data[0..sizeofheaders.unwrap() as usize])?;

        let binary = match self.macho.iter().nth(slice) {
            Some(binary) => binary,
            None => {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid Mach-O slice"));
            }
        };

        for segment in binary.segments() {
            let segment_virtual_address = segment.virtual_address();
            if segment_virtual_address > tempmap.size()? {
                let padding_length = segment_virtual_address - tempmap.size()?;
                tempmap.seek_to_end()?;
                tempmap.write_padding(padding_length as usize)?;
            }
            if !matches!(
                segment.command_type(),
                LoadCommandTypes::Segment | LoadCommandTypes::Segment64
            ) {
                continue;
            }
            let segment_file_offset = segment.file_offset() as usize;
            let segment_size = segment.file_size() as usize;
            if segment_file_offset + segment_size <= self.file.data.len() {
                tempmap.seek_to_end()?;
                tempmap.write(
                    &self.file.data[segment_file_offset..segment_file_offset + segment_size],
                )?;
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "macho slice segment size exceeds file data length",
                ));
            }
        }

        Ok(tempmap)
    }

    /// Returns the size of the MACHO file.
    ///
    /// # Returns
    /// The size of the file as a `u64`.
    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        self.file.size()
    }

    /// Returns the entropy of the MACHO file.
    ///
    /// # Returns
    /// The entropy of the file as a `Option<f64>`.
    #[allow(dead_code)]
    pub fn entropy(&self) -> Option<f64> {
        self.file.entropy()
    }

    /// Returns the TLS (Thread Local Storage) hash value if present in the MACHO file.
    ///
    /// # Returns
    /// An `Option<String>` containing the TLS hash if present, otherwise `None`.
    #[allow(dead_code)]
    pub fn tlsh(&self) -> Option<String> {
        self.file.tlsh()
    }

    /// Returns the SHA-256 hash value of the MACHO file.
    ///
    /// # Returns
    /// An `Option<String>` containing the SHA-256 hash if available, otherwise `None`.
    #[allow(dead_code)]
    pub fn sha256(&self) -> Option<String> {
        self.file.sha256()
    }

    /// Returns the File JSON associated with the PE
    ///
    /// # Returns
    /// An `Result<String, Error>` containing the File JSON.
    #[allow(dead_code)]
    pub fn file_json(&self) -> Result<String, Error> {
        self.file.json()
    }
}
