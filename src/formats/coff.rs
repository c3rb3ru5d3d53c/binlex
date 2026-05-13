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
use crate::formats::{Symbol as BlSymbol, symbol::SymbolKind};
use crate::hashing::SHA256;
use crate::hashing::SSDeep;
use crate::hashing::TLSH;
use std::collections::BTreeMap;
use std::io::{Error, ErrorKind};

const COFF_HEADER_SIZE: usize = 20;
const COFF_SECTION_HEADER_SIZE: usize = 40;
const COFF_SYMBOL_SIZE: usize = 18;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[derive(Clone, Copy)]
struct CoffHeader {
    machine: u16,
    number_of_sections: u16,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
}

#[derive(Clone)]
struct CoffSectionHeader {
    pointer_to_raw_data: u32,
    size_of_raw_data: u32,
    characteristics: u32,
}

pub struct COFF {
    header: CoffHeader,
    sections: Vec<CoffSectionHeader>,
    pub file: File,
    pub config: Configuration,
}

impl COFF {
    fn machine_to_architecture(machine: u16) -> Architecture {
        match machine {
            0x014c => Architecture::I386,
            0x8664 => Architecture::AMD64,
            0xAA64 => Architecture::ARM64,
            _ => Architecture::UNKNOWN,
        }
    }

    fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Error> {
        let end = offset
            .checked_add(2)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "coff offset overflow"))?;
        let slice = bytes
            .get(offset..end)
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "coff header truncated"))?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Error> {
        let end = offset
            .checked_add(4)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "coff offset overflow"))?;
        let slice = bytes
            .get(offset..end)
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "coff header truncated"))?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    fn parse_header(bytes: &[u8]) -> Result<CoffHeader, Error> {
        if bytes.len() < COFF_HEADER_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid coff file: missing file header",
            ));
        }
        Ok(CoffHeader {
            machine: Self::read_u16(bytes, 0)?,
            number_of_sections: Self::read_u16(bytes, 2)?,
            pointer_to_symbol_table: Self::read_u32(bytes, 8)?,
            number_of_symbols: Self::read_u32(bytes, 12)?,
            size_of_optional_header: Self::read_u16(bytes, 16)?,
        })
    }

    fn parse_sections(bytes: &[u8], header: CoffHeader) -> Result<Vec<CoffSectionHeader>, Error> {
        let section_table_offset = COFF_HEADER_SIZE
            .checked_add(header.size_of_optional_header as usize)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "coff section table overflow"))?;
        let section_table_size = (header.number_of_sections as usize)
            .checked_mul(COFF_SECTION_HEADER_SIZE)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "coff section count overflow"))?;
        let section_table_end = section_table_offset
            .checked_add(section_table_size)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "coff section table overflow"))?;
        if section_table_end > bytes.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid coff file: section table truncated",
            ));
        }

        let mut sections = Vec::with_capacity(header.number_of_sections as usize);
        for index in 0..header.number_of_sections as usize {
            let offset = section_table_offset + (index * COFF_SECTION_HEADER_SIZE);
            sections.push(CoffSectionHeader {
                pointer_to_raw_data: Self::read_u32(bytes, offset + 20)?,
                size_of_raw_data: Self::read_u32(bytes, offset + 16)?,
                characteristics: Self::read_u32(bytes, offset + 36)?,
            });
        }

        Ok(sections)
    }

    fn coff_symbol_name(name_bytes: &[u8; 8], string_table: &[u8]) -> Option<String> {
        if name_bytes[..4] == [0, 0, 0, 0] {
            let offset =
                u32::from_le_bytes([name_bytes[4], name_bytes[5], name_bytes[6], name_bytes[7]])
                    as usize;
            if offset < 4 || offset >= string_table.len() {
                return None;
            }
            let tail = &string_table[offset..];
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(tail.len());
            if end == 0 {
                return None;
            }
            return String::from_utf8(tail[..end].to_vec()).ok();
        }

        let end = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_bytes.len());
        if end == 0 {
            return None;
        }
        String::from_utf8(name_bytes[..end].to_vec()).ok()
    }

    fn string_table(&self) -> &[u8] {
        let pointer = self.header.pointer_to_symbol_table as usize;
        let table_size =
            match (self.header.number_of_symbols as usize).checked_mul(COFF_SYMBOL_SIZE) {
                Some(size) => size,
                None => return &[],
            };
        let table_end = match pointer.checked_add(table_size) {
            Some(end) => end,
            None => return &[],
        };
        if table_end + 4 > self.file.data.len() {
            return &[];
        }
        let size = u32::from_le_bytes(
            self.file.data[table_end..table_end + 4]
                .try_into()
                .expect("exact string table size slice"),
        ) as usize;
        if size < 4 || table_end + size > self.file.data.len() {
            return &[];
        }
        &self.file.data[table_end..table_end + size]
    }

    fn section_for_symbol(&self, section_number: i16) -> Option<&CoffSectionHeader> {
        if section_number <= 0 {
            return None;
        }
        self.sections.get((section_number - 1) as usize)
    }

    fn symbol_kind(symbol_type: u16) -> SymbolKind {
        if (symbol_type & 0x20) != 0 {
            SymbolKind::Function
        } else {
            SymbolKind::Unknown
        }
    }

    pub fn new(bytes: Vec<u8>, config: Configuration) -> Result<Self, Error> {
        let file = File::from_bytes(bytes, config.clone());
        let header = Self::parse_header(&file.data)?;
        let sections = Self::parse_sections(&file.data, header)?;
        Ok(Self {
            header,
            sections,
            file,
            config,
        })
    }

    pub fn architecture(&self) -> Architecture {
        Self::machine_to_architecture(self.header.machine)
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.file.data.clone()
    }

    pub fn size(&self) -> u64 {
        self.file.size()
    }

    pub fn executable_file_offset_ranges(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        for section in &self.sections {
            if section.pointer_to_raw_data == 0 || section.size_of_raw_data == 0 {
                continue;
            }
            if (section.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) == 0 {
                continue;
            }
            let start = section.pointer_to_raw_data as u64;
            result.insert(start, start + section.size_of_raw_data as u64);
        }
        result
    }

    pub fn symbols(&self) -> BTreeMap<u64, BlSymbol> {
        let mut symbols = BTreeMap::<u64, BlSymbol>::new();
        let pointer = self.header.pointer_to_symbol_table as usize;
        let count = self.header.number_of_symbols as usize;
        let table_size = match count.checked_mul(COFF_SYMBOL_SIZE) {
            Some(size) => size,
            None => return symbols,
        };
        let table_end = match pointer.checked_add(table_size) {
            Some(end) => end,
            None => return symbols,
        };
        if pointer == 0 || count == 0 || table_end > self.file.data.len() {
            return symbols;
        }

        let string_table = self.string_table();
        let mut index = 0usize;
        while index < count {
            let offset = pointer + (index * COFF_SYMBOL_SIZE);
            let record = &self.file.data[offset..offset + COFF_SYMBOL_SIZE];

            let name_bytes: [u8; 8] = record[0..8].try_into().expect("exact name slice");
            let value = u32::from_le_bytes(record[8..12].try_into().expect("exact value slice"));
            let section_number =
                i16::from_le_bytes(record[12..14].try_into().expect("exact section slice"));
            let symbol_type =
                u16::from_le_bytes(record[14..16].try_into().expect("exact type slice"));
            let aux_symbols = record[17] as usize;

            if let (Some(name), Some(section)) = (
                Self::coff_symbol_name(&name_bytes, string_table),
                self.section_for_symbol(section_number),
            ) {
                let offset = section.pointer_to_raw_data as u64 + value as u64;
                symbols.entry(offset).or_insert_with(|| BlSymbol {
                    name,
                    file_offset: offset,
                    virtual_address: None,
                    relative_virtual_address: None,
                    kind: Self::symbol_kind(symbol_type),
                });
            }

            index += 1 + aux_symbols;
        }

        symbols
    }

    pub fn file_offset_to_symbol(&self, file_offset: u64) -> Option<BlSymbol> {
        self.symbols()
            .into_values()
            .find(|symbol| symbol.file_offset == file_offset)
    }

    pub fn symbol_name_to_file_offset(&self, name: &str) -> Option<u64> {
        self.symbols()
            .into_values()
            .find_map(|symbol| (symbol.name == name).then_some(symbol.file_offset))
    }

    pub fn tlsh(&self) -> Option<TLSH<'_>> {
        self.file.tlsh()
    }

    pub fn sha256(&self) -> Option<SHA256<'_>> {
        self.file.sha256()
    }

    pub fn ssdeep(&self) -> Option<SSDeep<'_>> {
        self.file.ssdeep()
    }

    pub fn entropy(&self) -> Option<f64> {
        self.file.entropy()
    }

    pub fn file(&self) -> &File {
        &self.file
    }
}
