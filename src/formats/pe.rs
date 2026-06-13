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
use crate::formats::ImagePermissions;
use crate::formats::ImageSegment;
use crate::formats::cli::Cor20Header;
use crate::formats::cli::Entry;
use crate::formats::cli::FatHeader;
use crate::formats::cli::FieldEntry;
use crate::formats::cli::MetadataTable;
use crate::formats::cli::MetadataToken;
use crate::formats::cli::MethodDefEntry;
use crate::formats::cli::MethodHeader;
use crate::formats::cli::ModuleEntry;
use crate::formats::cli::StorageHeader;
use crate::formats::cli::StorageSignature;
use crate::formats::cli::StreamHeader;
use crate::formats::cli::TinyHeader;
use crate::formats::cli::TypeDefEntry;
use crate::formats::cli::TypeRefEntry;
use crate::formats::{Symbol as BlSymbol, symbol::SymbolKind};
use crate::hashing::SHA256;
use crate::hashing::SSDeep;
use crate::hashing::TLSH;
use lief::Binary;
use lief::generic::{Section, Symbol};
use lief::pe::data_directory::Type as DATA_DIRECTORY;
use lief::pe::debug::Entries;
use lief::pe::headers::MachineType;
use lief::pe::section::Characteristics;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::{Cursor, Error, ErrorKind};

/// Represents a PE (Portable Executable) file, encapsulating the `lief::pe::Binary` and associated metadata.
pub struct PE {
    pe: lief::pe::Binary,
    pub file: File,
    pub config: Configuration,
}

#[derive(Clone)]
pub struct ParsedStreamHeader {
    pub header: StreamHeader,
    pub name: Vec<u8>,
}

impl PE {
    fn dotnet_table_name(index: u64) -> &'static str {
        match index {
            0 => "Module",
            1 => "TypeRef",
            2 => "TypeDef",
            3 => "FieldPtr",
            4 => "Field",
            5 => "MethodPtr",
            6 => "MethodDef",
            7 => "ParamPtr",
            8 => "Param",
            9 => "InterfaceImpl",
            10 => "MemberRef",
            11 => "Constant",
            12 => "CustomAttribute",
            13 => "FieldMarshal",
            14 => "DeclSecurity",
            15 => "ClassLayout",
            16 => "FieldLayout",
            17 => "StandAloneSig",
            18 => "EventMap",
            19 => "EventPtr",
            20 => "Event",
            21 => "PropertyMap",
            22 => "PropertyPtr",
            23 => "Property",
            24 => "MethodSemantics",
            25 => "MethodImpl",
            26 => "ModuleRef",
            27 => "TypeSpec",
            28 => "ImplMap",
            29 => "FieldRva",
            30 => "EncLog",
            31 => "EncMap",
            32 => "Assembly",
            33 => "AssemblyProcessor",
            34 => "AssemblyOs",
            35 => "AssemblyRef",
            36 => "AssemblyRefProcessor",
            37 => "AssemblyRefOs",
            38 => "File",
            39 => "ExportedType",
            40 => "ManifestResource",
            41 => "NestedClass",
            42 => "GenericParam",
            43 => "MethodSpec",
            44 => "GenericParamConstraint",
            48 => "Document",
            49 => "MethodDebugInformation",
            50 => "LocalScope",
            51 => "LocalVariable",
            52 => "LocalConstant",
            53 => "ImportScope",
            54 => "StateMachineMethod",
            55 => "CustomDebugInformation",
            _ => "Unknown",
        }
    }

    fn dotnet_table_id(name: &str) -> Option<u64> {
        (0..64).find(|index| Self::dotnet_table_name(*index) == name)
    }

    fn dotnet_metadata_token(table_index: u64, rid: u64) -> u64 {
        (table_index << 24) | rid
    }

    fn dotnet_metadata_token_string(table_index: u64, rid: u64) -> String {
        format!("0x{:08x}", Self::dotnet_metadata_token(table_index, rid))
    }

    fn parse_dotnet_metadata_token(value: &str) -> Option<u64> {
        if let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            return u64::from_str_radix(hex, 16).ok();
        }
        value.parse::<u64>().ok()
    }

    fn dotnet_bytes_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }

    fn dotnet_compressed_u32(bytes: &[u8], offset: usize) -> Option<(u32, usize)> {
        let first = *bytes.get(offset)?;
        if first & 0x80 == 0 {
            Some((first as u32, 1))
        } else if first & 0xC0 == 0x80 {
            let second = *bytes.get(offset + 1)?;
            Some(((((first & 0x3F) as u32) << 8) | second as u32, 2))
        } else if first & 0xE0 == 0xC0 {
            let second = *bytes.get(offset + 1)?;
            let third = *bytes.get(offset + 2)?;
            let fourth = *bytes.get(offset + 3)?;
            Some((
                (((first & 0x1F) as u32) << 24)
                    | ((second as u32) << 16)
                    | ((third as u32) << 8)
                    | fourth as u32,
                4,
            ))
        } else {
            None
        }
    }

    fn dotnet_string_index_metadata(&self, index: &crate::formats::cli::StringHeapIndex) -> Value {
        json!({
            "heap": "#Strings",
            "index": index.offset,
            "size": index.size,
            "value": self.dotnet_string(index),
        })
    }

    fn dotnet_guid_index_metadata(&self, index: &crate::formats::cli::GuidHeapIndex) -> Value {
        json!({
            "heap": "#GUID",
            "index": index.offset,
            "size": index.size,
        })
    }

    fn dotnet_blob_bytes(&self, index: &crate::formats::cli::BlobHeapIndex) -> Option<Vec<u8>> {
        if index.offset == 0 {
            return None;
        }
        let blobs = self.dotnet_stream_data("#Blob")?;
        let offset = index.offset as usize;
        if offset >= blobs.len() {
            return None;
        }
        let (length, header_size) = Self::dotnet_compressed_u32(blobs, offset)?;
        let start = offset.checked_add(header_size)?;
        let end = start.checked_add(length as usize)?;
        (end <= blobs.len()).then(|| blobs[start..end].to_vec())
    }

    fn dotnet_blob_index_metadata(&self, index: &crate::formats::cli::BlobHeapIndex) -> Value {
        let raw = self
            .dotnet_blob_bytes(index)
            .map(|bytes| Self::dotnet_bytes_hex(&bytes));
        json!({
            "heap": "#Blob",
            "index": index.offset,
            "size": index.size,
            "raw": raw,
        })
    }

    fn dotnet_simple_table_index_metadata(
        table: &str,
        index: &crate::formats::cli::SimpleTableIndex,
    ) -> Value {
        json!({
            "table": table,
            "rid": index.offset,
            "size": index.size,
        })
    }

    fn dotnet_typedef_or_ref_metadata(index: &crate::formats::cli::TypeDefOrRefIndex) -> Value {
        let tag = index.offset & 0x3;
        let rid = index.offset >> 2;
        let table = match tag {
            0 => "TypeDef",
            1 => "TypeRef",
            2 => "TypeSpec",
            _ => "Unknown",
        };
        let token = Self::dotnet_table_id(table)
            .filter(|_| rid != 0)
            .map(|table_id| Self::dotnet_metadata_token_string(table_id, rid as u64));
        json!({
            "coded_index": "TypeDefOrRef",
            "table": table,
            "rid": rid,
            "token": token,
            "raw": index.offset,
            "size": index.size,
        })
    }

    fn dotnet_resolution_scope_metadata(
        index: &crate::formats::cli::ResolutionScopeIndex,
    ) -> Value {
        let tag = index.offset & 0x3;
        let rid = index.offset >> 2;
        let table = match tag {
            0 => "Module",
            1 => "ModuleRef",
            2 => "AssemblyRef",
            3 => "TypeRef",
            _ => "Unknown",
        };
        let token = Self::dotnet_table_id(table)
            .filter(|_| rid != 0)
            .map(|table_id| Self::dotnet_metadata_token_string(table_id, rid as u64));
        json!({
            "coded_index": "ResolutionScope",
            "table": table,
            "rid": rid,
            "token": token,
            "raw": index.offset,
            "size": index.size,
        })
    }

    fn dotnet_method_body_metadata(&self, rva: u32) -> Option<Value> {
        if rva == 0 {
            return None;
        }
        let header_virtual_address = self.relative_virtual_address_to_virtual_address(rva as u64);
        let header = self.dotnet_method_header(header_virtual_address).ok()?;
        let header_size = header.size()?;
        let code_size = header.code_size()?;
        let code_virtual_address = header_virtual_address + header_size as u64;
        let file_offset = self.virtual_address_to_file_offset(header_virtual_address);
        let code_file_offset = self.virtual_address_to_file_offset(code_virtual_address);
        let mut result = json!({
            "relative_virtual_address": rva,
            "header_virtual_address": header_virtual_address,
            "header_file_offset": file_offset,
            "code_virtual_address": code_virtual_address,
            "code_file_offset": code_file_offset,
            "header_size": header_size,
            "code_size": code_size,
        });
        if let Value::Object(ref mut object) = result {
            match header {
                MethodHeader::Tiny(header) => {
                    object.insert("format".to_string(), json!("tiny"));
                    object.insert("max_stack".to_string(), json!(8));
                    object.insert("init_locals".to_string(), json!(false));
                    object.insert("local_var_sig_token".to_string(), Value::Null);
                    object.insert("flags".to_string(), json!(0));
                    object.insert("tiny_flags".to_string(), json!(header.code_size));
                }
                MethodHeader::Fat(header) => {
                    object.insert("format".to_string(), json!("fat"));
                    object.insert("max_stack".to_string(), json!(header.max_stack));
                    object.insert("init_locals".to_string(), json!((header.flags & 0x10) != 0));
                    object.insert(
                        "local_var_sig_token".to_string(),
                        json!(format!("0x{:08x}", header.local_var_sig_token)),
                    );
                    object.insert("flags".to_string(), json!(header.flags));
                }
            }
        }
        Some(result)
    }

    fn dotnet_strings_heap_metadata(&self) -> Value {
        let mut strings = Vec::<Value>::new();
        let Some(data) = self.dotnet_stream_data("#Strings") else {
            return json!({ "strings": strings });
        };

        let mut offset = 1usize;
        while offset < data.len() {
            let tail = &data[offset..];
            let Some(length) = tail.iter().position(|byte| *byte == 0) else {
                break;
            };
            if length > 0 {
                strings.push(json!({
                    "index": offset,
                    "value": String::from_utf8_lossy(&tail[..length]).to_string(),
                }));
            }
            offset += length + 1;
        }

        json!({
            "strings": strings,
        })
    }

    fn dotnet_user_strings_heap_metadata(&self) -> Value {
        let mut strings = Vec::<Value>::new();
        let Some(data) = self.dotnet_stream_data("#US") else {
            return json!({ "strings": strings });
        };

        let mut offset = 1usize;
        while offset < data.len() {
            let Some((length, header_size)) = Self::dotnet_compressed_u32(data, offset) else {
                break;
            };
            if length == 0 {
                offset += header_size;
                continue;
            }

            let start = match offset.checked_add(header_size) {
                Some(start) => start,
                None => break,
            };
            let end = match start.checked_add(length as usize) {
                Some(end) if end <= data.len() => end,
                _ => break,
            };

            let payload = &data[start..end];
            let string_bytes = payload
                .get(..payload.len().saturating_sub(1))
                .unwrap_or(payload);
            let code_units = string_bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<_>>();
            strings.push(json!({
                "index": offset,
                "token": format!("0x{:08x}", 0x7000_0000u64 | offset as u64),
                "value": String::from_utf16_lossy(&code_units),
                "raw": Self::dotnet_bytes_hex(payload),
            }));

            offset = end;
        }

        json!({
            "strings": strings,
        })
    }

    fn dotnet_heaps_metadata(&self) -> Value {
        json!({
            "#Strings": self.dotnet_strings_heap_metadata(),
            "#US": self.dotnet_user_strings_heap_metadata(),
        })
    }

    fn dotnet_push_table_row(tables: &mut serde_json::Map<String, Value>, table: &str, row: Value) {
        let table_id = Self::dotnet_table_id(table).unwrap_or(u64::MAX);
        let entry = tables.entry(table.to_string()).or_insert_with(|| {
            json!({
                "id": table_id,
                "rows": [],
            })
        });
        if let Some(rows) = entry.get_mut("rows").and_then(Value::as_array_mut) {
            rows.push(row);
        }
    }

    fn dotnet_stream_name(header: &ParsedStreamHeader) -> String {
        let bytes = &header.name;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).to_string()
    }

    fn dotnet_stream_data(&self, stream_name: &str) -> Option<&[u8]> {
        let (_, storage_signature) = self.dotnet_parse_storage_signature()?;
        let metadata_rva = self.dotnet_cor20_header()?.meta_data.virtual_address as u64;
        let metadata_offset = self.relative_virtual_address_to_file_offset(metadata_rva)? as usize;
        for header in self.dotnet_stream_headers() {
            if Self::dotnet_stream_name(&header) != stream_name {
                continue;
            }
            let start = metadata_offset.checked_add(header.header.offset as usize)?;
            let end = start.checked_add(header.header.size as usize)?;
            if end > self.file.data.len() {
                return None;
            }
            let _ = storage_signature;
            return Some(&self.file.data[start..end]);
        }
        None
    }

    fn dotnet_string(&self, index: &crate::formats::cli::StringHeapIndex) -> Option<String> {
        if index.offset == 0 {
            return None;
        }
        let strings = self.dotnet_stream_data("#Strings")?;
        let start = index.offset as usize;
        if start >= strings.len() {
            return None;
        }
        let tail = &strings[start..];
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(tail.len());
        if end == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&tail[..end]).to_string())
    }

    fn coff_symbol_name(&self, name_bytes: &[u8; 8], string_table: &[u8]) -> Option<String> {
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

    fn coff_symbol_kind(symbol_type: u16) -> SymbolKind {
        if (symbol_type & 0x20) != 0 {
            SymbolKind::Function
        } else {
            SymbolKind::Unknown
        }
    }

    fn coff_symbols(&self) -> BTreeMap<u64, BlSymbol> {
        const COFF_SYMBOL_SIZE: usize = 18;

        let mut symbols = BTreeMap::<u64, BlSymbol>::new();
        let pointer = self.pe.header().pointerto_symbol_table() as usize;
        let count = self.pe.header().numberof_symbols() as usize;
        if pointer == 0 || count == 0 {
            return symbols;
        }

        let table_size = match count.checked_mul(COFF_SYMBOL_SIZE) {
            Some(size) => size,
            None => return symbols,
        };
        let table_end = match pointer.checked_add(table_size) {
            Some(end) => end,
            None => return symbols,
        };
        if table_end > self.file.data.len() {
            return symbols;
        }

        let string_table = if table_end + 4 <= self.file.data.len() {
            let size = u32::from_le_bytes(
                self.file.data[table_end..table_end + 4]
                    .try_into()
                    .expect("slice with exact length"),
            ) as usize;
            if size >= 4 && table_end + size <= self.file.data.len() {
                &self.file.data[table_end..table_end + size]
            } else {
                &self.file.data[table_end..]
            }
        } else {
            &[]
        };

        let sections = self.pe.sections().collect::<Vec<_>>();
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

            if section_number > 0 {
                if let Some(name) = self.coff_symbol_name(&name_bytes, string_table) {
                    let section_index = (section_number - 1) as usize;
                    if let Some(section) = sections.get(section_index) {
                        let virtual_address =
                            self.imagebase() + section.virtual_address() + value as u64;
                        let kind = Self::coff_symbol_kind(symbol_type);
                        symbols.entry(virtual_address).or_insert_with(|| {
                            self.symbol_from_virtual_address(name, virtual_address, kind)
                        });
                    }
                }
            }

            index += 1 + aux_symbols;
        }

        symbols
    }

    fn normalize_symbol_address(&self, raw: u64) -> u64 {
        if raw >= self.imagebase() {
            raw
        } else {
            self.imagebase() + raw
        }
    }

    fn symbol_from_virtual_address(
        &self,
        name: String,
        virtual_address: u64,
        kind: SymbolKind,
    ) -> BlSymbol {
        BlSymbol {
            name,
            file_offset: self
                .virtual_address_to_file_offset(virtual_address)
                .unwrap_or(0),
            virtual_address: Some(virtual_address),
            relative_virtual_address: Some(
                self.virtual_address_to_relative_virtual_address(virtual_address),
            ),
            kind,
        }
    }

    fn dotnet_clr_runtime_directory(&self) -> Option<lief::pe::DataDirectory<'_>> {
        let directory = self
            .pe
            .data_directory_by_type(DATA_DIRECTORY::CLR_RUNTIME_HEADER)?;
        if directory.rva() == 0 || directory.size() < Cor20Header::size() as u32 {
            return None;
        }
        Some(directory)
    }

    /// Creates a new `PE` instance from a byte vector containing PE file data.
    pub fn new(bytes: Vec<u8>, config: Configuration) -> Result<Self, Error> {
        let file = File::from_bytes(bytes, config.clone());
        let mut cursor = Cursor::new(&file.data);
        if let Some(Binary::PE(pe)) = Binary::from(&mut cursor) {
            return Ok(Self { pe, file, config });
        }
        Err(Error::new(ErrorKind::InvalidInput, "invalid pe file"))
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.file.data.clone()
    }

    /// Converts a relative virtual address to a file offset
    ///
    /// # Returns
    /// The file offset as a `Option<u64>`.
    pub fn relative_virtual_address_to_file_offset(&self, rva: u64) -> Option<u64> {
        for section in self.pe.sections() {
            let section_start_rva = section.virtual_address();
            let section_end_rva = section_start_rva + section.virtual_size() as u64;
            if rva >= section_start_rva && rva < section_end_rva {
                let section_offset = rva - section_start_rva;
                let file_offset = section.pointerto_raw_data() as u64 + section_offset;
                return Some(file_offset);
            }
        }
        None
    }

    /// Parses the .NET Core 2.0 header from the PE file if it is a .NET executable.
    ///
    /// This function attempts to locate and parse the CLR runtime header by resolving its
    /// virtual address and reading its data from the file. If successful, it returns the
    /// file offset of the header and a reference to the parsed `Cor20Header` structure.
    ///
    /// # Returns
    ///
    /// * `Option<(u64, &Cor20Header)>` - A tuple containing:
    ///   * The file offset of the header as `u64`.
    ///   * A reference to the parsed `Cor20Header` structure.
    /// * `None` - If the file is not a .NET executable or the header cannot be parsed.
    fn dotnet_parse_cor20_header(&self) -> Option<(u64, Cor20Header)> {
        let clr_runtime_header = self.dotnet_clr_runtime_directory()?;
        let start = self.relative_virtual_address_to_file_offset(clr_runtime_header.rva() as u64)?;
        let end = start + Cor20Header::size() as u64;
        if end as usize > self.file.data.len() {
            return None;
        }
        let data = &self.file.data[start as usize..end as usize];
        let header = Cor20Header::from_bytes(data)?;
        Some((start, header))
    }

    /// Retrieves the .NET Core 2.0 header from the PE file if it is a .NET executable.
    ///
    /// This function provides a simpler interface to access the `Cor20Header` directly
    /// by internally calling `dotnet_parse_cor20_header` and returning only the header.
    ///
    /// # Returns
    ///
    /// * `Option<&Cor20Header>` - A reference to the parsed `Cor20Header` structure.
    /// * `None` - If the file is not a .NET executable or the header cannot be parsed.
    pub fn dotnet_cor20_header(&self) -> Option<Cor20Header> {
        Some(self.dotnet_parse_cor20_header()?.1)
    }

    /// Parses the .NET storage signature from the metadata of a PE file.
    ///
    /// This function attempts to locate and parse the storage signature in the
    /// metadata section of the PE file, based on the metadata virtual address
    /// specified in the `Cor20Header`.
    ///
    /// # Returns
    ///
    /// * `Option<(u64, &StorageSignature)>` - A tuple containing:
    ///   * The file offset of the storage signature as `u64`.
    ///   * A reference to the parsed `StorageSignature` structure.
    /// * `None` - If the file is not a .NET executable or the storage signature
    ///   cannot be parsed.
    fn dotnet_parse_storage_signature(&self) -> Option<(u64, StorageSignature)> {
        let (_, image_cor20_header) = self.dotnet_parse_cor20_header()?;
        let rva = image_cor20_header.meta_data.virtual_address as u64;
        let start = self.relative_virtual_address_to_file_offset(rva)? as usize;
        let end = start + StorageSignature::size();
        if end > self.file.data.len() {
            return None;
        }
        let data = &self.file.data[start..end];
        let header = StorageSignature::from_bytes(data)?;
        Some((start as u64, header))
    }

    /// Retrieves the .NET storage signature from the metadata of a PE file.
    ///
    /// This function provides a simpler interface to access the `StorageSignature` directly
    /// by internally calling `dotnet_parse_storage_signature` and returning only the signature.
    ///
    /// # Returns
    ///
    /// * `Option<&StorageSignature>` - A reference to the parsed `StorageSignature` structure.
    /// * `None` - If the file is not a .NET executable or the storage signature cannot be parsed.
    pub fn dotnet_storage_signature(&self) -> Option<StorageSignature> {
        Some(self.dotnet_parse_storage_signature()?.1)
    }

    /// Parses the .NET storage header from the metadata of a PE file.
    ///
    /// This function attempts to locate and parse the `StorageHeader` in the metadata
    /// section of the PE file. It calculates the starting position based on the size of
    /// the `StorageSignature` and the version string, then reads and parses the
    /// header data.
    ///
    /// # Returns
    ///
    /// * `Option<(u64, &StorageHeader)>` - A tuple containing:
    ///   * The file offset of the storage header as `u64`.
    ///   * A reference to the fparsed `StorageHeader` structure.
    /// * `None` - If the file is not a .NET executable or the storage header cannot be parsed.
    fn dotnet_parse_storage_header(&self) -> Option<(u64, StorageHeader)> {
        let (mut start, cor20_storage_signaure_header) = self.dotnet_parse_storage_signature()?;
        start += StorageSignature::size() as u64;
        start += cor20_storage_signaure_header.version_string_size as u64;
        start -= 4;
        let end = start as usize + StorageHeader::size();
        if end > self.file.data.len() {
            return None;
        }
        let data = &self.file.data[start as usize..end];
        let header = StorageHeader::from_bytes(data)?;
        Some((start, header))
    }

    /// Retrieves the .NET storage header from the metadata of a PE file.
    ///
    /// This function provides a simpler interface to access the `StorageHeader` directly
    /// by internally calling `dotnet_parse_storage_header` and returning only the header.
    ///
    /// # Returns
    ///
    /// * `Option<&StorageHeader>` - A reference to the parsed `StorageHeader` structure.
    /// * `None` - If the file is not a .NET executable or the storage header cannot be parsed.
    pub fn dotnet_storage_header(&self) -> Option<StorageHeader> {
        Some(self.dotnet_parse_storage_header()?.1)
    }

    /// Parses the .NET stream headers from the metadata of a PE file.
    ///
    /// This function reads and parses the stream headers defined in the metadata section
    /// of the PE file. It calculates the starting position based on the `StorageHeader`
    /// and iterates through the number of streams specified, creating a `BTreeMap` of the
    /// file offsets and their corresponding `StreamHeader` structures.
    ///
    /// # Returns
    ///
    /// * `Option<BTreeMap<u64, &StreamHeader>>` - A map where:
    ///   * The keys are the file offsets of the stream headers as `u64`.
    ///   * The values are references to the parsed `StreamHeader` structures.
    /// * `None` - If the file is not a .NET executable, the storage header cannot be parsed,
    ///   or no stream headers are found.
    fn dotnet_parse_stream_headers(&self) -> Option<BTreeMap<u64, ParsedStreamHeader>> {
        let (cor20_storage_header_offset, cor20_storage_header) =
            self.dotnet_parse_storage_header()?;
        let mut offset = cor20_storage_header_offset as usize + StorageHeader::size();
        let mut result = BTreeMap::<u64, ParsedStreamHeader>::new();
        for _ in 0..cor20_storage_header.number_of_streams {
            if offset + StreamHeader::size() > self.file.data.len() {
                return None;
            }
            let data = &self.file.data[offset..];
            let header = StreamHeader::from_bytes(data)?;
            let name = header.name(data)?.to_vec();
            result.insert(
                offset as u64,
                ParsedStreamHeader {
                    header,
                    name: name.clone(),
                },
            );
            offset += StreamHeader::size() + name.len();
        }
        if result.is_empty() {
            return None;
        }
        Some(result)
    }

    /// Retrieves the .NET stream headers from the metadata of a PE file as a vector.
    ///
    /// This function provides a simpler interface to access the `StreamHeader` structures
    /// directly by internally calling `dotnet_parse_stream_headers` and returning only the
    /// parsed headers in a vector.
    ///
    /// # Returns
    ///
    /// * `Vec<&StreamHeader>` - A vector of references to the parsed `StreamHeader` structures.
    /// * An empty vector - If the file is not a .NET executable or the stream headers cannot
    ///   be parsed.
    pub fn dotnet_stream_headers(&self) -> Vec<ParsedStreamHeader> {
        let mut result = Vec::<ParsedStreamHeader>::new();
        let headers = self.dotnet_parse_stream_headers();
        if headers.is_none() {
            return result;
        }
        for (_, header) in headers.unwrap() {
            result.push(header);
        }
        result
    }

    /// Parses the .NET metadata table from the metadata of a PE file.
    ///
    /// This function locates and parses the `MetadataTable` in the metadata section of the
    /// PE file. It identifies the stream header with the `#~` name, calculates the correct
    /// offset based on its location and the storage signature, and reads the metadata table data.
    ///
    /// # Returns
    ///
    /// * `Option<(u64, &MetadataTable)>` - A tuple containing:
    ///   * The file offset of the metadata table as `u64`.
    ///   * A reference to the parsed `MetadataTable` structure.
    /// * `None` - If the file is not a .NET executable, the relevant stream header cannot
    ///   be found, or the metadata table cannot be parsed.
    fn dotnet_parse_metadata_table(&self) -> Option<(u64, MetadataTable)> {
        let (mut start, _) = self.dotnet_parse_storage_signature()?;
        for (_, header) in self.dotnet_parse_stream_headers()? {
            if header.name == vec![0x23, 0x7e, 0x00, 0x00] {
                start += header.header.offset as u64;
            }
        }
        if start as usize + MetadataTable::size() > self.file.data.len() {
            return None;
        }
        let data = &self.file.data[start as usize..start as usize + MetadataTable::size()];
        Some((start, MetadataTable::from_bytes(data)?))
    }

    /// Retrieves the .NET metadata table from the metadata of a PE file.
    ///
    /// This function provides a simpler interface to access the `MetadataTable` directly
    /// by internally calling `dotnet_parse_metadata_table` and returning only the parsed table.
    ///
    /// # Returns
    ///
    /// * `Option<&MetadataTable>` - A reference to the parsed `MetadataTable` structure.
    /// * `None` - If the file is not a .NET executable or the metadata table cannot be parsed.
    pub fn dotnet_metadata_table(&self) -> Option<MetadataTable> {
        Some(self.dotnet_parse_metadata_table()?.1)
    }

    /// Parses and retrieves the entries from the .NET metadata table of a PE file.
    ///
    /// This function iterates through the metadata table entries specified in the
    /// `MetadataTable` structure, reading and parsing each entry based on its type
    /// (e.g., `Module`, `TypeRef`, `TypeDef`, `Field`, `MethodDef`). The function calculates
    /// the correct offsets, validates entry counts, and constructs a vector of parsed entries.
    ///
    /// # Returns
    ///
    /// * `Option<Vec<Entry>>` - A vector containing parsed entries from the metadata table.
    ///   Each entry is wrapped in the `Entry` enum to represent its specific type.
    /// * `None` - If the file is not a .NET executable, the metadata table cannot be parsed,
    ///   or an error occurs during entry parsing.
    ///
    /// # Notes
    ///
    /// * This function uses `MetadataToken` to determine the type of each metadata table entry.
    /// * The parsing depends on the `heap_sizes` field in the `MetadataTable` to correctly interpret
    ///   data sizes within entries.
    /// * If an invalid offset or entry count is encountered, the function will return `None`.
    pub fn dotnet_metadata_table_entries(&self) -> Option<Vec<Entry>> {
        if !self.is_dotnet() {
            return None;
        }

        let (cor20_metadata_table_offset, cor20_metadata_table) =
            self.dotnet_parse_metadata_table()?;

        let mut offset: usize = cor20_metadata_table_offset as usize
            + MetadataTable::size()
            + cor20_metadata_table.mask_valid.count_ones() as usize * 4;

        let mut valid_index: usize = 0;

        let mut entries = Vec::<Entry>::new();

        for i in 0..64 {
            if (cor20_metadata_table.mask_valid & (1u64 << i)) == 0 {
                continue;
            }

            let entry_offset =
                cor20_metadata_table_offset as usize + MetadataTable::size() + (valid_index * 4);

            if entry_offset + 4 > self.file.data.len() {
                return None;
            }

            let entry_count = u32::from_le_bytes(
                self.file.data[entry_offset..entry_offset + 4]
                    .try_into()
                    .unwrap(),
            ) as usize;

            match i {
                x if x == MetadataToken::Module as usize => {
                    for _ in 0..entry_count {
                        let entry = ModuleEntry::from_bytes(
                            &self.file.data[offset..],
                            cor20_metadata_table.heap_sizes,
                        )?;
                        offset += entry.size();
                        entries.push(Entry::Module(entry));
                    }
                }
                x if x == MetadataToken::TypeRef as usize => {
                    for _ in 0..entry_count {
                        let entry = TypeRefEntry::from_bytes(
                            &self.file.data[offset..],
                            cor20_metadata_table.heap_sizes,
                        )?;
                        offset += entry.size();
                        entries.push(Entry::TypeRef(entry));
                    }
                }
                x if x == MetadataToken::TypeDef as usize => {
                    for _ in 0..entry_count {
                        let entry = TypeDefEntry::from_bytes(
                            &self.file.data[offset..],
                            cor20_metadata_table.heap_sizes,
                        )?;
                        offset += entry.size();
                        entries.push(Entry::TypeDef(entry));
                    }
                }
                x if x == MetadataToken::Field as usize => {
                    for _ in 0..entry_count {
                        let entry = FieldEntry::from_bytes(
                            &self.file.data[offset..],
                            cor20_metadata_table.heap_sizes,
                        )?;
                        offset += entry.size();
                        entries.push(Entry::Field(entry));
                    }
                }
                x if x == MetadataToken::MethodDef as usize => {
                    for _ in 0..entry_count {
                        let entry = MethodDefEntry::from_bytes(
                            &self.file.data[offset..],
                            cor20_metadata_table.heap_sizes,
                        )?;
                        offset += entry.size();
                        entries.push(Entry::MethodDef(entry));
                    }
                }
                _ => {}
            }

            valid_index += 1;
        }

        Some(entries)
    }

    /// Builds canonical metadata for a .NET PE using logical CLI metadata tables.
    ///
    /// The returned value is intentionally table-oriented: rows keep their RID and token,
    /// heap references preserve their source heap/index, and resolved values are embedded
    /// when the parser can resolve them cheaply. Helper accessors derive from this layout
    /// instead of serializing separate convenience maps.
    pub fn metadata(&self) -> Value {
        let mut result = json!({
            "format": "pe",
        });

        if !self.is_dotnet() {
            return result;
        }

        let cor20_header = self.dotnet_cor20_header();
        let storage_signature = self.dotnet_storage_signature();
        let storage_header = self.dotnet_storage_header();
        let metadata_table = self.dotnet_metadata_table();

        let streams = self
            .dotnet_stream_headers()
            .into_iter()
            .map(|header| {
                let name = Self::dotnet_stream_name(&header);
                (
                    name,
                    json!({
                        "offset": header.header.offset,
                        "size": header.header.size,
                    }),
                )
            })
            .collect::<serde_json::Map<String, Value>>();

        let present_tables = metadata_table
            .map(|table| {
                (0..64)
                    .filter(|index| (table.mask_valid & (1u64 << index)) != 0)
                    .map(|index| {
                        json!({
                            "id": index,
                            "name": Self::dotnet_table_name(index),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let entries = self.dotnet_metadata_table_entries().unwrap_or_default();
        let mut tables = serde_json::Map::<String, Value>::new();

        let mut module_rid = 0u64;
        let mut type_ref_rid = 0u64;
        let mut type_def_rid = 0u64;
        let mut field_rid = 0u64;
        let mut method_def_rid = 0u64;

        for entry in entries {
            match entry {
                Entry::Module(entry) => {
                    module_rid += 1;
                    Self::dotnet_push_table_row(
                        &mut tables,
                        "Module",
                        json!({
                            "rid": module_rid,
                            "token": Self::dotnet_metadata_token_string(MetadataToken::Module as u64, module_rid),
                            "generation": entry.generation,
                            "name": self.dotnet_string_index_metadata(&entry.name),
                            "mvid": self.dotnet_guid_index_metadata(&entry.mv_id),
                            "enc_id": self.dotnet_guid_index_metadata(&entry.enc_id),
                            "enc_base_id": self.dotnet_guid_index_metadata(&entry.enc_base_id),
                        }),
                    );
                }
                Entry::TypeRef(entry) => {
                    type_ref_rid += 1;
                    Self::dotnet_push_table_row(
                        &mut tables,
                        "TypeRef",
                        json!({
                            "rid": type_ref_rid,
                            "token": Self::dotnet_metadata_token_string(MetadataToken::TypeRef as u64, type_ref_rid),
                            "resolution_scope": Self::dotnet_resolution_scope_metadata(&entry.resolution_scope),
                            "name": self.dotnet_string_index_metadata(&entry.name),
                            "namespace": self.dotnet_string_index_metadata(&entry.namespace),
                        }),
                    );
                }
                Entry::TypeDef(entry) => {
                    type_def_rid += 1;
                    Self::dotnet_push_table_row(
                        &mut tables,
                        "TypeDef",
                        json!({
                            "rid": type_def_rid,
                            "token": Self::dotnet_metadata_token_string(MetadataToken::TypeDef as u64, type_def_rid),
                            "flags": entry.flags,
                            "name": self.dotnet_string_index_metadata(&entry.name),
                            "namespace": self.dotnet_string_index_metadata(&entry.namespace),
                            "extends": Self::dotnet_typedef_or_ref_metadata(&entry.extends),
                            "field_list": Self::dotnet_simple_table_index_metadata("Field", &entry.field_list),
                            "method_list": Self::dotnet_simple_table_index_metadata("MethodDef", &entry.method_list),
                        }),
                    );
                }
                Entry::Field(entry) => {
                    field_rid += 1;
                    Self::dotnet_push_table_row(
                        &mut tables,
                        "Field",
                        json!({
                            "rid": field_rid,
                            "token": Self::dotnet_metadata_token_string(MetadataToken::Field as u64, field_rid),
                            "flags": entry.flags,
                            "name": self.dotnet_string_index_metadata(&entry.name),
                            "signature": self.dotnet_blob_index_metadata(&entry.signature),
                        }),
                    );
                }
                Entry::MethodDef(entry) => {
                    method_def_rid += 1;
                    Self::dotnet_push_table_row(
                        &mut tables,
                        "MethodDef",
                        json!({
                            "rid": method_def_rid,
                            "token": Self::dotnet_metadata_token_string(MetadataToken::MethodDef as u64, method_def_rid),
                            "rva": entry.rva,
                            "impl_flags": entry.impl_flags,
                            "flags": entry.flags,
                            "name": self.dotnet_string_index_metadata(&entry.name),
                            "signature": self.dotnet_blob_index_metadata(&entry.signature),
                            "param_list": Self::dotnet_simple_table_index_metadata("Param", &entry.param_list),
                            "body": self.dotnet_method_body_metadata(entry.rva),
                        }),
                    );
                }
            }
        }

        let cil = json!({
            "metadata": {
                "cor20_header": cor20_header.map(|header| json!({
                    "cb": header.cb,
                    "major_runtime_version": header.major_runtime_version,
                    "minor_runtime_version": header.minor_runtime_version,
                    "metadata": {
                        "relative_virtual_address": header.meta_data.virtual_address,
                        "virtual_address": self.relative_virtual_address_to_virtual_address(header.meta_data.virtual_address as u64),
                        "size": header.meta_data.size,
                    },
                    "flags": header.flags,
                    "resources": {
                        "relative_virtual_address": header.resources.virtual_address,
                        "size": header.resources.size,
                    },
                    "strong_name_signature": {
                        "relative_virtual_address": header.strong_name_signature.virtual_address,
                        "size": header.strong_name_signature.size,
                    },
                })),
                "storage": {
                    "signature": storage_signature.map(|signature| json!({
                        "signature": signature.signature,
                        "major_version": signature.major_version,
                        "minor_version": signature.minor_version,
                        "extra_data": signature.extra_data,
                        "version_string_size": signature.version_string_size,
                    })),
                    "header": storage_header.map(|header| json!({
                        "flags": header.flags,
                        "number_of_streams": header.number_of_streams,
                    })),
                },
                "streams": streams,
                "heaps": self.dotnet_heaps_metadata(),
                "tables_header": metadata_table.map(|table| json!({
                    "reserved": table.reserved,
                    "major_version": table.major_version,
                    "minor_version": table.minor_version,
                    "heap_sizes": table.heap_sizes,
                    "rid": table.rid,
                    "mask_valid": table.mask_valid,
                    "mask_sorted": table.mask_sorted,
                    "present_tables": present_tables,
                })),
                "tables": tables,
            }
        });

        if let Value::Object(ref mut object) = result {
            object.insert("cil".to_string(), cil);
        }

        result
    }

    /// Computes a .NET metadata token from a given table index and entry index.
    ///
    /// # Parameters
    /// - `table_index`: The index of the metadata table.
    /// - `entry_index`: The index of the entry within the table.
    ///
    /// # Returns
    /// A `u64` value representing the metadata token. The calculation is based on the formula:
    /// `(0x01000000 * table_index) + (entry_index + 1)`.
    pub fn dotnet_metadata_token_from_index(table_index: u64, entry_index: u64) -> u64 {
        (0x01000000 * table_index) + entry_index + 1
    }

    /// Constructs a map of metadata tokens to their corresponding virtual addresses.
    ///
    /// This function analyzes the .NET metadata table entries and calculates the virtual
    /// addresses for `MethodDef` entries. Each metadata token is generated based on the entry's
    /// index in the metadata table and is mapped to the computed virtual address.
    ///
    /// # Returns
    ///
    /// A `BTreeMap<u64, u64>` where:
    /// - The key is the metadata token.
    /// - The value is the corresponding virtual address.
    pub fn dotnet_metadata_token_virtual_addresses(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        let metadata = self.metadata();
        let rows = metadata
            .get("cil")
            .and_then(|cil| cil.get("metadata"))
            .and_then(|metadata| metadata.get("tables"))
            .and_then(|tables| tables.get("MethodDef"))
            .and_then(|table| table.get("rows"))
            .and_then(Value::as_array);

        let Some(rows) = rows else {
            return result;
        };

        for row in rows {
            let token = row
                .get("token")
                .and_then(Value::as_str)
                .and_then(Self::parse_dotnet_metadata_token);
            let address = row
                .get("body")
                .and_then(Value::as_object)
                .and_then(|body| body.get("code_virtual_address"))
                .and_then(Value::as_u64);
            if let (Some(token), Some(address)) = (token, address) {
                result.insert(token, address);
            }
        }
        result
    }

    /// Resolves a .NET metadata token to its corresponding virtual address.
    ///
    /// This helper currently supports `MethodDef` metadata tokens and returns the
    /// virtual address of the first CIL instruction in the method body.
    ///
    /// # Parameters
    /// - `metadata_token`: The .NET metadata token to resolve.
    ///
    /// # Returns
    /// * `Some(u64)` - The virtual address associated with the metadata token.
    /// * `None` - If the token is not present or cannot be resolved.
    pub fn dotnet_metadata_token_to_virtual_address(&self, metadata_token: u64) -> Option<u64> {
        self.dotnet_metadata_token_virtual_addresses()
            .get(&metadata_token)
            .copied()
    }

    /// Resolves a .NET metadata token to its corresponding relative virtual address.
    ///
    /// This helper currently supports `MethodDef` metadata tokens and returns the
    /// relative virtual address of the first CIL instruction in the method body.
    pub fn dotnet_metadata_token_to_relative_virtual_address(
        &self,
        metadata_token: u64,
    ) -> Option<u64> {
        let address = self.dotnet_metadata_token_to_virtual_address(metadata_token)?;
        Some(self.virtual_address_to_relative_virtual_address(address))
    }

    /// Resolves a .NET metadata token to its corresponding file offset.
    ///
    /// This helper currently supports `MethodDef` metadata tokens and returns the
    /// file offset of the first CIL instruction in the method body.
    pub fn dotnet_metadata_token_to_file_offset(&self, metadata_token: u64) -> Option<u64> {
        let address = self.dotnet_metadata_token_to_virtual_address(metadata_token)?;
        self.virtual_address_to_file_offset(address)
    }

    /// Resolves a .NET method body virtual address back to its metadata token.
    ///
    /// This helper currently supports `MethodDef` metadata tokens and expects the
    /// virtual address of the first CIL instruction in the method body.
    pub fn dotnet_virtual_address_to_metadata_token(&self, virtual_address: u64) -> Option<u64> {
        self.dotnet_metadata_token_virtual_addresses()
            .into_iter()
            .find_map(|(token, address)| (address == virtual_address).then_some(token))
    }

    /// Resolves a .NET method body relative virtual address back to its metadata token.
    ///
    /// This helper currently supports `MethodDef` metadata tokens and expects the
    /// relative virtual address of the first CIL instruction in the method body.
    pub fn dotnet_relative_virtual_address_to_metadata_token(
        &self,
        relative_virtual_address: u64,
    ) -> Option<u64> {
        let address = self.relative_virtual_address_to_virtual_address(relative_virtual_address);
        self.dotnet_virtual_address_to_metadata_token(address)
    }

    /// Resolves a .NET method body file offset back to its metadata token.
    ///
    /// This helper currently supports `MethodDef` metadata tokens and expects the
    /// file offset of the first CIL instruction in the method body.
    pub fn dotnet_file_offset_to_metadata_token(&self, file_offset: u64) -> Option<u64> {
        let address = self.file_offset_to_virtual_address(file_offset)?;
        self.dotnet_virtual_address_to_metadata_token(address)
    }

    /// Converts a virtual address to a relative virtual address (RVA).
    ///
    /// This function computes the relative virtual address by subtracting the image base
    /// address of the file from the given virtual address.
    ///
    /// # Parameters
    ///
    /// * `address` - The virtual address (`u64`) to be converted.
    ///
    /// # Returns
    ///
    /// * `u64` - The relative virtual address (RVA).
    pub fn virtual_address_to_relative_virtual_address(&self, address: u64) -> u64 {
        address - self.imagebase()
    }

    /// Converts a file offset to a relative virtual address (RVA).
    ///
    /// This function first resolves the file offset to a virtual address and then
    /// converts that virtual address to a relative virtual address.
    ///
    /// # Parameters
    ///
    /// * `file_offset` - The file offset (`u64`) to be converted.
    ///
    /// # Returns
    ///
    /// * `Option<u64>` - The relative virtual address corresponding to the file
    ///   offset, or `None` if the conversion fails.
    pub fn file_offset_to_relative_virtual_address(&self, file_offset: u64) -> Option<u64> {
        let address = self.file_offset_to_virtual_address(file_offset)?;
        Some(self.virtual_address_to_relative_virtual_address(address))
    }

    /// Converts a virtual address to a file offset in the PE file.
    ///
    /// This function first converts the virtual address to a relative virtual address (RVA)
    /// using `virtual_address_to_relative_virtual_address` and then resolves the RVA to a
    /// file offset using `relative_virtual_address_to_file_offset`.
    ///
    /// # Parameters
    ///
    /// * `address` - The virtual address (`u64`) to be converted.
    ///
    /// # Returns
    ///
    /// * `Option<u64>` - The file offset corresponding to the given virtual address, or
    ///   `None` if the conversion fails.
    pub fn virtual_address_to_file_offset(&self, address: u64) -> Option<u64> {
        let rva = self.virtual_address_to_relative_virtual_address(address);
        self.relative_virtual_address_to_file_offset(rva)
    }

    /// Parses and retrieves a method header from a given virtual address in the PE file.
    ///
    /// This function identifies and parses the method header (either Tiny or Fat)
    /// associated with the given virtual address. The header type is determined based
    /// on specific bits in the header's first byte. If the address is invalid or the
    /// data does not correspond to a valid method header, an error is returned.
    ///
    /// # Parameters
    ///
    /// * `address` - The virtual address (`u64`) of the method header.
    ///
    /// # Returns
    ///
    /// * `Result<MethodHeader, Error>` -
    ///   * `Ok(MethodHeader)` - The parsed method header as either `Tiny` or `Fat`.
    ///   * `Err(Error)` - If the virtual address is invalid or the data is not a valid method header.
    pub fn dotnet_method_header(&self, address: u64) -> Result<MethodHeader, Error> {
        let offset = self.virtual_address_to_file_offset(address);

        if offset.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "failed to convert virtual address to file offset",
            ));
        }

        let bytes = &self.file.data[offset.unwrap() as usize..offset.unwrap() as usize + 12];

        if bytes[0] & 0b11 == 0b10 {
            let code_size = bytes[0] >> 2;
            let tiny_header = TinyHeader { code_size };
            return Ok(MethodHeader::Tiny(tiny_header));
        }
        if bytes[0] & 0b11 == 0b11 {
            let fat_header = FatHeader::from_bytes(bytes)?;
            return Ok(MethodHeader::Fat(fat_header));
        }
        Err(Error::new(ErrorKind::InvalidData, "invalid method header"))
    }

    /// Checks if the PE file is a .NET assembly.
    ///
    /// This function inspects the imports of the PE file to identify whether it is a .NET application.
    /// It does so by looking for the presence of specific .NET-related DLLs (`mscorelib.dll` and `mscoree.dll`)
    /// in the import table and confirming the existence of a CLR runtime header.
    ///
    /// # Returns
    ///
    /// - `true` if the PE file is a .NET assembly.
    /// - `false` otherwise.
    #[allow(dead_code)]
    pub fn is_dotnet(&self) -> bool {
        let Some((_, cor20_header)) = self.dotnet_parse_cor20_header() else {
            return false;
        };
        if cor20_header.cb < Cor20Header::size() as u32 {
            return false;
        }
        if cor20_header.meta_data.virtual_address == 0 || cor20_header.meta_data.size == 0 {
            return false;
        }
        matches!(
            self.dotnet_storage_signature()
                .map(|signature| signature.signature),
            Some(0x424A_5342)
        )
    }

    /// Creates a new `PE` instance from a byte vector containing PE file data.
    ///
    /// Returns the architecture of the PE file based on its machine type.
    ///
    /// # Returns
    /// The `BinaryArchitecture` enum value corresponding to the PE machine type (e.g., AMD64, I386, CIL or UNKNOWN).
    #[allow(dead_code)]
    pub fn architecture(&self) -> Architecture {
        if self.is_dotnet() {
            return Architecture::CIL;
        }

        match self.pe.header().machine() {
            MachineType::I386 => Architecture::I386,
            MachineType::AMD64 => Architecture::AMD64,
            MachineType::ARM64 => Architecture::ARM64,
            _ => Architecture::UNKNOWN,
        }
    }

    /// Retrieves the virtual address ranges of executable methods in a .NET executable.
    ///
    /// This function scans the .NET metadata table for `MethodDef` entries and computes
    /// the virtual address ranges for executable methods. It uses the relative virtual
    /// address (RVA) of each method to determine its virtual address and extracts the
    /// method's header to calculate the start and end addresses of the method's executable code.
    ///
    /// # Returns
    ///
    /// * `BTreeMap<u64, u64>` - A map where:
    ///   * Keys represent the start of the method's executable code (virtual address).
    ///   * Values represent the end of the method's executable code (virtual address).
    pub fn dotnet_executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        let metadata = self.metadata();
        let rows = metadata
            .get("cil")
            .and_then(|cil| cil.get("metadata"))
            .and_then(|metadata| metadata.get("tables"))
            .and_then(|tables| tables.get("MethodDef"))
            .and_then(|table| table.get("rows"))
            .and_then(Value::as_array);

        let Some(rows) = rows else {
            return result;
        };

        for row in rows {
            let body = row.get("body").and_then(Value::as_object);
            let start = body
                .and_then(|body| body.get("code_virtual_address"))
                .and_then(Value::as_u64);
            let size = body
                .and_then(|body| body.get("code_size"))
                .and_then(Value::as_u64);
            if let (Some(start), Some(size)) = (start, size) {
                result.insert(start, start + size);
            }
        }
        result
    }

    /// Identifies and returns a set of virtual addresses that belong to vtable entries
    /// within executable sections of a PE file.
    ///
    /// This function scans all sections of a PE file to find consecutive virtual addresses
    /// that are considered executable. It filters the sections based on their characteristics
    /// and excludes certain edge cases, such as .NET binaries.
    ///
    /// # Returns
    /// - A `BTreeSet` of `u64` representing executable vtable virtual addresses.
    pub fn vtable_executable_virtual_addresses(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();

        if self.is_dotnet() {
            return result;
        }

        let executable_virtual_address_ranges = self.executable_virtual_address_ranges();

        for section in self.pe.sections() {
            if (section.characteristics().bits() & u64::from(Characteristics::MEM_EXECUTE)) != 0
                || section.virtual_size() == 0
                || section.sizeof_raw_data() == 0
            {
                continue;
            }

            let start_offset = match self
                .relative_virtual_address_to_file_offset(section.pointerto_raw_data() as u64)
            {
                Some(offset) => offset,
                None => continue,
            };

            let end_offset = start_offset + section.sizeof_raw_data() as u64;

            let mut consecutive_addresses = Vec::new();

            for offset in (start_offset as usize..end_offset as usize).step_by(4) {
                if offset + 4 > self.file.data.len() {
                    break;
                }

                let virtual_address = self.imagebase()
                    + u32::from_le_bytes(self.file.data[offset..offset + 4].try_into().unwrap())
                        as u64;

                if executable_virtual_address_ranges
                    .iter()
                    .any(|(start, end)| virtual_address >= *start && virtual_address <= *end)
                {
                    consecutive_addresses.push(virtual_address);

                    if consecutive_addresses.len() >= 6 {
                        result.extend(&consecutive_addresses);
                        consecutive_addresses.clear();
                    }
                } else {
                    consecutive_addresses.clear();
                }
            }
        }

        result
    }

    /// Returns the ranges of executable memory addresses within the PE file.
    ///
    /// This includes sections marked as executable (`MEM_EXECUTE`) and with valid data.
    ///
    /// # Returns
    /// A `BTreeMap` where the key is the start address of the executable range and the value is the end address.
    #[allow(dead_code)]
    pub fn native_executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        for section in self.pe.sections() {
            if (section.characteristics().bits() & u64::from(Characteristics::MEM_EXECUTE)) == 0 {
                continue;
            }
            if section.virtual_size() == 0 {
                continue;
            }
            if section.sizeof_raw_data() == 0 {
                continue;
            }
            let section_virtual_adddress = PE::align_section_virtual_address(
                self.imagebase() + section.virtual_address(),
                self.section_alignment(),
                self.file_alignment(),
            );
            result.insert(
                section_virtual_adddress,
                section_virtual_adddress + section.virtual_size() as u64,
            );
        }
        result
    }

    #[allow(dead_code)]
    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        if self.is_dotnet() {
            return self.dotnet_executable_virtual_address_ranges();
        }
        self.native_executable_virtual_address_ranges()
    }

    /// Returns a map of Pogo (debug) entries found in the PE file, keyed by their start RVA (Relative Virtual Address).
    ///
    /// # Returns
    /// A `HashMap` where the key is the RVA of the start of the Pogo entry and the value is the name of the entry.
    ///
    #[allow(dead_code)]
    pub fn pogo_virtual_addresses(&self) -> HashMap<u64, String> {
        let mut result = HashMap::<u64, String>::new();
        for entry in self.pe.debug() {
            if let Entries::Pogo(pogos) = entry {
                for pogo in pogos.entries() {
                    result.insert(self.imagebase() + pogo.start_rva() as u64, pogo.name());
                }
            }
        }
        result
    }

    /// Returns a set of TLS (Thread Local Storage) callback addresses in the PE file.
    ///
    /// The method retrieves the TLS callbacks from the PE file's TLS data directory, if present.
    /// TLS callbacks are functions that are called when a thread is created or terminated, and they
    /// are often used in applications to initialize or clean up thread-local data.
    ///
    /// # Returns
    /// A `BTreeSet<u64>` containing the addresses of the TLS callback functions.
    pub fn tlscallback_virtual_addresses(&self) -> BTreeSet<u64> {
        self.pe
            .tls()
            .into_iter()
            .flat_map(|tls| tls.callbacks())
            .collect()
    }

    /// Returns a set of dotnet function virtual addresses in the PE file.
    ///
    /// # Returns
    /// A `BTreeSet` of function addresses in the PE file.
    pub fn dotnet_entrypoint_virtual_addresses(&self) -> BTreeSet<u64> {
        let mut addresses = BTreeSet::<u64>::new();
        let metadata = self.metadata();
        let rows = metadata
            .get("cil")
            .and_then(|cil| cil.get("metadata"))
            .and_then(|metadata| metadata.get("tables"))
            .and_then(|tables| tables.get("MethodDef"))
            .and_then(|table| table.get("rows"))
            .and_then(Value::as_array);

        let Some(rows) = rows else {
            return addresses;
        };

        for row in rows {
            if let Some(address) = row
                .get("body")
                .and_then(Value::as_object)
                .and_then(|body| body.get("code_virtual_address"))
                .and_then(Value::as_u64)
            {
                addresses.insert(address);
            }
        }
        addresses
    }

    /// Returns a set of function addresses (entry point, exports, TLS callbacks, and Pogo entries) in the PE file.
    ///
    /// # Returns
    /// A `BTreeSet` of function addresses in the PE file.
    #[allow(dead_code)]
    pub fn native_entrypoint_virtual_addresses(&self) -> BTreeSet<u64> {
        let mut addresses = BTreeSet::<u64>::new();
        addresses.insert(self.entrypoint_virtual_address());
        addresses.extend(self.export_virtual_addresses());
        addresses.extend(self.tlscallback_virtual_addresses());
        addresses.extend(self.pogo_virtual_addresses().keys().cloned());
        addresses.extend(self.vtable_executable_virtual_addresses());
        addresses
    }

    #[allow(dead_code)]
    pub fn entrypoint_virtual_addresses(&self) -> BTreeSet<u64> {
        if self.is_dotnet() {
            return self.dotnet_entrypoint_virtual_addresses();
        }
        self.native_entrypoint_virtual_addresses()
    }

    /// Returns the entry point address of the PE file.
    ///
    /// # Returns
    /// The entry point address as a `u64` value.
    #[allow(dead_code)]
    pub fn entrypoint_virtual_address(&self) -> u64 {
        self.imagebase() + self.pe.optional_header().addressof_entrypoint() as u64
    }

    /// Returns the size of the headers of the PE file.
    ///
    /// # Returns
    /// The size of the headers as a `u64` value.
    #[allow(dead_code)]
    pub fn sizeofheaders(&self) -> u64 {
        self.pe.optional_header().sizeof_headers() as u64
    }

    /// Aligns a section's virtual address to the specified section and file alignment boundaries.
    ///
    /// # Parameters
    /// - `value`: The virtual address to align.
    /// - `section_alignment`: The section alignment boundary.
    /// - `file_alignment`: The file alignment boundary.
    ///
    /// # Returns
    /// The aligned virtual address.
    #[allow(dead_code)]
    pub fn align_section_virtual_address(
        value: u64,
        mut section_alignment: u64,
        file_alignment: u64,
    ) -> u64 {
        if section_alignment < 0x1000 {
            section_alignment = file_alignment;
        }
        if section_alignment != 0 && (value % section_alignment) != 0 {
            return value.div_ceil(section_alignment) * section_alignment;
        }
        value
    }

    /// Returns the section alignment used in the PE file.
    ///
    /// # Returns
    /// The section alignment value as a `u64`.
    #[allow(dead_code)]
    pub fn section_alignment(&self) -> u64 {
        self.pe.optional_header().section_alignment() as u64
    }

    /// Returns the file alignment used in the PE file.
    ///
    /// # Returns
    /// The file alignment value as a `u64`.
    #[allow(dead_code)]
    pub fn file_alignment(&self) -> u64 {
        self.pe.optional_header().file_alignment() as u64
    }

    /// Converts a relative virtual address to a virtual address
    ///
    /// # Returns
    /// The virtual address as a `u64`.
    #[allow(dead_code)]
    pub fn relative_virtual_address_to_virtual_address(
        &self,
        relative_virtual_address: u64,
    ) -> u64 {
        self.imagebase() + relative_virtual_address
    }

    /// Converts a file offset to a virtual address.
    ///
    /// This method looks through the PE file's sections to determine which section contains the file offset.
    /// It then computes the corresponding virtual address within that section.
    ///
    /// # Parameters
    /// - `file_offset`: The file offset (raw data offset) to convert to a virtual address.
    ///
    /// # Returns
    /// The corresponding virtual address as a `u64`.
    #[allow(dead_code)]
    pub fn file_offset_to_virtual_address(&self, file_offset: u64) -> Option<u64> {
        for section in self.pe.sections() {
            let section_raw_data_offset = section.pointerto_raw_data() as u64;
            let section_raw_data_size = section.sizeof_raw_data() as u64;
            if file_offset >= section_raw_data_offset
                && file_offset < section_raw_data_offset + section_raw_data_size
            {
                let section_virtual_address = self.imagebase() + section.virtual_address();
                let section_offset = file_offset - section_raw_data_offset;
                let virtual_address = section_virtual_address + section_offset;
                return Some(virtual_address);
            }
        }
        None
    }

    /// Builds a virtual image from PE headers and sections.
    pub fn image(&self) -> Result<Image, Error> {
        let mut image = Image::new();
        let image_base = self.imagebase();
        let headers_size = (self.sizeofheaders() as usize).min(self.file.data.len());
        if headers_size > 0 {
            image.add_segment(ImageSegment::bytes(
                Some("headers".to_string()),
                image_base,
                self.file.data[0..headers_size].to_vec(),
                ImagePermissions::readable(),
            ));
        }
        for section in self.pe.sections() {
            if section.virtual_size() == 0 {
                continue;
            }
            let permissions = if (section.characteristics().bits()
                & u64::from(Characteristics::MEM_EXECUTE))
                != 0
            {
                ImagePermissions::executable()
            } else {
                ImagePermissions::readable()
            };
            let section_virtual_adddress = PE::align_section_virtual_address(
                section.virtual_address(),
                self.section_alignment(),
                self.file_alignment(),
            );
            let section_virtual_address = image_base + section_virtual_adddress;
            let pointerto_raw_data = section.pointerto_raw_data() as usize;
            let sizeof_raw_data = section.sizeof_raw_data() as usize;
            let raw_available = self.file.data.len().saturating_sub(pointerto_raw_data);
            let raw_size = sizeof_raw_data.min(raw_available);
            if raw_size > 0 {
                image.add_segment(ImageSegment::bytes(
                    Some(section.name().to_string()),
                    section_virtual_address,
                    self.file.data[pointerto_raw_data..pointerto_raw_data + raw_size].to_vec(),
                    permissions,
                ));
            }
            let virtual_size = u64::from(section.virtual_size());
            if virtual_size > raw_size as u64 {
                image.add_segment(ImageSegment::zeroes(
                    Some(section.name().to_string()),
                    section_virtual_address + raw_size as u64,
                    virtual_size - raw_size as u64,
                    permissions,
                ));
            }
        }
        Ok(image)
    }

    /// Returns the size of the PE file.
    ///
    /// # Returns
    /// The size of the file as a `u64`.
    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        self.file.size()
    }

    /// Returns the entropy of the PE file.
    ///
    /// # Returns
    /// The entropy of the file as a `Option<f64>`.
    #[allow(dead_code)]
    pub fn entropy(&self) -> Option<f64> {
        self.file.entropy()
    }

    /// Returns the TLS (Thread Local Storage) hash value if present in the PE file.
    ///
    /// # Returns
    /// An `Option<TLSH>` containing the TLSH helper if present, otherwise `None`.
    #[allow(dead_code)]
    pub fn tlsh(&self) -> Option<TLSH<'_>> {
        self.file.tlsh()
    }

    /// Returns the SHA-256 hash value of the PE file.
    ///
    /// # Returns
    /// An `Option<SHA256>` containing the SHA-256 helper if available, otherwise `None`.
    #[allow(dead_code)]
    pub fn sha256(&self) -> Option<SHA256<'_>> {
        self.file.sha256()
    }

    /// Returns the ssdeep hash value of the PE file.
    #[allow(dead_code)]
    pub fn ssdeep(&self) -> Option<SSDeep<'_>> {
        self.file.ssdeep()
    }

    /// Returns the underlying file metadata helper associated with the PE.
    ///
    /// # Returns
    /// A borrowed [`File`] reference for the PE input.
    #[allow(dead_code)]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Returns the base address (image base) of the PE file.
    ///
    /// # Returns
    /// The image base address as a `u64`.
    #[allow(dead_code)]
    pub fn imagebase(&self) -> u64 {
        self.pe.optional_header().imagebase()
    }

    /// Returns a set of exported function addresses in the PE file.
    ///
    /// # Returns
    /// A `BTreeSet` of exported function addresses.
    #[allow(dead_code)]
    pub fn export_virtual_addresses(&self) -> BTreeSet<u64> {
        let mut addresses = BTreeSet::<u64>::new();
        let export = match self.pe.export() {
            Some(export) => export,
            None => {
                return addresses;
            }
        };
        for entry in export.entries() {
            let address = entry.address() as u64 + self.imagebase();
            addresses.insert(address);
        }
        addresses
    }

    pub fn native_symbols(&self) -> BTreeMap<u64, BlSymbol> {
        let mut symbols = self.coff_symbols();

        if let Some(export) = self.pe.export() {
            for entry in export.entries() {
                let name = entry.name();
                if name.is_empty() {
                    continue;
                }
                let address = self.imagebase() + entry.address() as u64;
                symbols.insert(
                    address,
                    self.symbol_from_virtual_address(name, address, SymbolKind::Export),
                );
            }
        }

        for import in self.pe.imports() {
            let library = import.name();
            for entry in import.entries() {
                let name = match entry.name() {
                    name if !name.is_empty() => name,
                    _ if entry.is_ordinal() => format!("ordinal_{}", entry.ordinal()),
                    _ => continue,
                };
                let address = self.normalize_symbol_address(entry.iat_address());
                symbols.entry(address).or_insert_with(|| {
                    self.symbol_from_virtual_address(
                        format!("{library}!{name}"),
                        address,
                        SymbolKind::Import,
                    )
                });
            }
        }

        for import in self.pe.delay_imports() {
            let library = import.name();
            for entry in import.entries() {
                let name = match entry.name() {
                    name if !name.is_empty() => name,
                    _ if entry.is_ordinal() => format!("ordinal_{}", entry.ordinal()),
                    _ => continue,
                };
                let address = self.normalize_symbol_address(entry.value());
                symbols.entry(address).or_insert_with(|| {
                    self.symbol_from_virtual_address(
                        format!("{library}!{name}"),
                        address,
                        SymbolKind::Import,
                    )
                });
            }
        }

        symbols
    }

    pub fn dotnet_symbols(&self) -> BTreeMap<u64, BlSymbol> {
        let mut symbols = BTreeMap::<u64, BlSymbol>::new();
        let metadata = self.metadata();
        let tables = metadata
            .get("cil")
            .and_then(|cil| cil.get("metadata"))
            .and_then(|metadata| metadata.get("tables"));

        let Some(tables) = tables else {
            return symbols;
        };

        let type_def_rows = tables
            .get("TypeDef")
            .and_then(|table| table.get("rows"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let method_def_rows = tables
            .get("MethodDef")
            .and_then(|table| table.get("rows"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        let mut method_owner_names = vec![None::<String>; method_def_rows.len()];
        for (type_index, type_definition) in type_def_rows.iter().enumerate() {
            let start = type_definition
                .get("method_list")
                .and_then(|value| value.get("rid"))
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .saturating_sub(1) as usize;
            let end = type_def_rows
                .get(type_index + 1)
                .and_then(|next| next.get("method_list"))
                .and_then(|value| value.get("rid"))
                .and_then(Value::as_u64)
                .map(|rid| rid.saturating_sub(1) as usize)
                .unwrap_or(method_def_rows.len());
            let type_name = type_definition
                .get("name")
                .and_then(|value| value.get("value"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let type_namespace = type_definition
                .get("namespace")
                .and_then(|value| value.get("value"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let qualified_name = if type_namespace.is_empty() {
                type_name.to_string()
            } else if type_name.is_empty() {
                type_namespace.to_string()
            } else {
                format!("{type_namespace}.{type_name}")
            };
            for owner_slot in method_owner_names
                .iter_mut()
                .take(end.min(method_def_rows.len()))
                .skip(start.min(method_def_rows.len()))
            {
                *owner_slot = Some(qualified_name.clone());
            }
        }

        for (index, method) in method_def_rows.iter().enumerate() {
            let Some(address) = method
                .get("body")
                .and_then(Value::as_object)
                .and_then(|body| body.get("code_virtual_address"))
                .and_then(Value::as_u64)
            else {
                continue;
            };
            let method_name = method
                .get("name")
                .and_then(|value| value.get("value"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .unwrap_or_else(|| format!("method_{}", index + 1));
            let qualified_name = match method_owner_names.get(index).and_then(|name| name.as_ref())
            {
                Some(owner) if !owner.is_empty() => format!("{owner}::{method_name}"),
                _ => method_name,
            };

            symbols.insert(
                address,
                self.symbol_from_virtual_address(qualified_name, address, SymbolKind::Function),
            );
        }

        symbols
    }

    pub fn symbols(&self) -> BTreeMap<u64, BlSymbol> {
        let mut symbols = self.native_symbols();
        symbols.extend(self.dotnet_symbols());
        symbols
    }

    pub fn virtual_address_to_symbol(&self, virtual_address: u64) -> Option<BlSymbol> {
        self.symbols().get(&virtual_address).cloned()
    }

    pub fn symbol_name_to_virtual_address(&self, name: &str) -> Option<u64> {
        self.symbols()
            .into_iter()
            .find_map(|(virtual_address, symbol)| (symbol.name == name).then_some(virtual_address))
    }

    pub fn symbol_name_to_file_offset(&self, name: &str) -> Option<u64> {
        self.symbols()
            .into_values()
            .find_map(|symbol| (symbol.name == name).then_some(symbol.file_offset))
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
}
