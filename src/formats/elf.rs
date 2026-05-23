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

use crate::Architecture;
use crate::Configuration;
use crate::formats::File;
use crate::formats::Image;
use crate::formats::{Symbol as BlSymbol, symbol::SymbolKind};
use crate::hashing::SHA256;
use crate::hashing::SSDeep;
use crate::hashing::TLSH;
use lief::Binary;
use lief::elf::section::Flags;
use lief::elf::segment::Type as SegmentType;
use lief::elf::symbol::Type as ElfSymbolType;
use lief::generic::{Section, Symbol};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::{Cursor, Error, ErrorKind};
use std::path::PathBuf;

pub const DEFAULT_IMAGEBASE: u64 = 0x100000;

pub struct ELF {
    elf: lief::elf::Binary,
    pub file: File,
    pub config: Configuration,
}

impl ELF {
    fn symbol_name(symbol: &lief::elf::Symbol<'_>) -> String {
        let base = symbol.name();
        if let Some(version) = symbol.symbol_version()
            && let Some(aux) = version.symbol_version_auxiliary()
        {
            let provider = aux.name();
            if !provider.is_empty() {
                return format!("{base}!{provider}");
            }
        }
        base
    }

    fn symbol_file_offset(&self, symbol: &lief::elf::Symbol<'_>) -> u64 {
        let virtual_address = symbol.value();
        if let Some(offset) = self.virtual_address_to_file_offset(virtual_address) {
            return offset;
        }
        if let Some(section) = symbol.section() {
            return section.file_offset() + virtual_address;
        }
        0
    }

    pub fn new(bytes: Vec<u8>, config: Configuration) -> Result<Self, Error> {
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
            183 => Architecture::ARM64,
            _ => Architecture::UNKNOWN,
        };
        architecture
    }

    pub fn entrypoint_virtual_address(&self) -> u64 {
        self.elf.header().entrypoint()
    }

    pub fn imagebase(&self) -> u64 {
        self.elf
            .segments()
            .filter(|segment| segment.p_type() == SegmentType::LOAD)
            .map(|segment| segment.virtual_address())
            .min()
            .unwrap_or(DEFAULT_IMAGEBASE)
    }

    pub fn size(&self) -> u64 {
        self.file.size()
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.file.data.clone()
    }

    pub fn export_virtual_addresses(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        for symbol in self.elf.exported_symbols() {
            result.insert(symbol.value());
        }
        result
    }

    pub fn symbols(&self) -> BTreeMap<u64, BlSymbol> {
        let mut symbols = self
            .elf
            .dynamic_symbols()
            .chain(self.elf.exported_symbols())
            .chain(self.elf.imported_symbols())
            .chain(self.elf.symtab_symbols())
            .filter(|symbol| symbol.get_type() == ElfSymbolType::FUNC)
            .map(|symbol| {
                let virtual_address = symbol.value();
                let offset = self.symbol_file_offset(&symbol);
                let name = Self::symbol_name(&symbol);
                (
                    virtual_address,
                    BlSymbol {
                        name,
                        file_offset: offset,
                        virtual_address: Some(virtual_address),
                        relative_virtual_address: Some(virtual_address - self.imagebase()),
                        kind: SymbolKind::Function,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        for (virtual_address, symbol) in self.plt_symbols() {
            symbols.entry(virtual_address).or_insert(symbol);
        }

        symbols
    }

    fn plt_symbols(&self) -> BTreeMap<u64, BlSymbol> {
        let Some(plt_section) = self.elf.section_by_name(".plt") else {
            return BTreeMap::new();
        };

        let relocations = self.elf.pltgot_relocations().collect::<Vec<_>>();
        if relocations.is_empty() {
            return BTreeMap::new();
        }

        let (entry_size, reserved_size) = match self.architecture() {
            Architecture::AMD64 | Architecture::I386 => (16u64, 16u64),
            Architecture::ARM64 => (16u64, 32u64),
            _ => return BTreeMap::new(),
        };

        if plt_section.size() < reserved_size + entry_size {
            return BTreeMap::new();
        }

        let plt_start = plt_section.virtual_address();
        let mut result = BTreeMap::new();

        for (index, relocation) in relocations.into_iter().enumerate() {
            let Some(symbol) = relocation.symbol() else {
                continue;
            };

            let name = Self::symbol_name(&symbol);
            if name.is_empty() {
                continue;
            }

            let virtual_address = plt_start + reserved_size + (index as u64 * entry_size);
            let file_offset = match self.virtual_address_to_file_offset(virtual_address) {
                Some(offset) => offset,
                None => continue,
            };

            result.insert(
                virtual_address,
                BlSymbol {
                    name,
                    file_offset,
                    virtual_address: Some(virtual_address),
                    relative_virtual_address: Some(virtual_address - self.imagebase()),
                    kind: SymbolKind::Function,
                },
            );
        }

        result
    }

    pub fn virtual_address_to_symbol(&self, virtual_address: u64) -> Option<BlSymbol> {
        self.symbols().get(&virtual_address).cloned()
    }

    pub fn symbol_name_to_virtual_address(&self, name: &str) -> Option<u64> {
        let mut fallback = None;
        for (virtual_address, symbol) in self.symbols() {
            if symbol.name != name {
                continue;
            }
            if virtual_address != 0 {
                return Some(virtual_address);
            }
            fallback = Some(virtual_address);
        }
        fallback
    }

    pub fn symbol_name_to_file_offset(&self, name: &str) -> Option<u64> {
        let mut fallback = None;
        for symbol in self.symbols().into_values() {
            if symbol.name != name {
                continue;
            }
            if symbol.virtual_address != Some(0) {
                return Some(symbol.file_offset);
            }
            fallback = Some(symbol.file_offset);
        }
        fallback
    }

    pub fn relative_virtual_address_to_symbol(
        &self,
        relative_virtual_address: u64,
    ) -> Option<BlSymbol> {
        let virtual_address =
            self.relative_virtual_address_to_virtual_address(relative_virtual_address);
        self.virtual_address_to_symbol(virtual_address)
    }

    pub fn file_offset_to_symbol(&self, file_offset: u64) -> Option<BlSymbol> {
        self.symbols()
            .into_values()
            .find(|symbol| symbol.file_offset == file_offset)
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
                let segment_virtual_address = segment.virtual_address();
                return Some(segment_virtual_address + (file_offset - start));
            }
        }
        None
    }

    pub fn virtual_address_to_file_offset(&self, virtual_address: u64) -> Option<u64> {
        for segment in self.elf.segments() {
            let start = segment.virtual_address();
            let end = start + segment.virtual_size();
            if virtual_address >= start && virtual_address < end {
                return Some(segment.file_offset() + (virtual_address - start));
            }
        }
        None
    }

    pub fn image(&self) -> Result<Image, Error> {
        let pathbuf = PathBuf::from(self.config.mmap.directory.clone()).join(format!(
            "{}.mapped-v2",
            self.file.sha256_no_config().unwrap()
        ));
        let mut tempmap = Image::new(pathbuf, self.config.mmap.cache.enabled)?;
        let image_base = self.imagebase();
        tempmap.set_base(image_base);

        if tempmap.is_cached() {
            return Ok(tempmap);
        }

        tempmap.seek_to_end()?;
        tempmap.write(&self.file.data[0..self.elf.header().header_size() as usize])?;

        for segment in self.elf.segments() {
            let segment_virtual_address = segment.virtual_address().saturating_sub(image_base);

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

    pub fn tlsh(&self) -> Option<TLSH<'_>> {
        self.file.tlsh()
    }

    pub fn sha256(&self) -> Option<SHA256<'_>> {
        self.file.sha256()
    }

    #[allow(dead_code)]
    pub fn ssdeep(&self) -> Option<SSDeep<'_>> {
        self.file.ssdeep()
    }

    /// Returns the entropy of the ELF file.
    ///
    /// # Returns
    /// The entropy of the file as a `Option<f64>`.
    #[allow(dead_code)]
    pub fn entropy(&self) -> Option<f64> {
        self.file.entropy()
    }

    /// Returns the underlying file metadata helper associated with the ELF.
    ///
    /// # Returns
    /// A borrowed [`File`] reference for the ELF input.
    #[allow(dead_code)]
    pub fn file(&self) -> &File {
        &self.file
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
                let start = section.virtual_address();
                let end = start + section.size();
                result.insert(start, end);
            }
        }
        result
    }
}
