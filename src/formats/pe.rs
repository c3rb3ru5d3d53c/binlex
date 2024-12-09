use lief::generic::Section;
use lief::Binary;
use lief::pe::section::Characteristics;
use std::io::{Cursor, Error, ErrorKind};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::path::PathBuf;
use lief::pe::headers::MachineType;
use crate::Architecture;
use crate::formats::File;
use std::collections::BTreeMap;
use lief::pe::debug::Entries;
use crate::types::MemoryMappedFile;
use crate::Config;
use lief::pe::data_directory::Type as DATA_DIRECTORY;
use crate::formats::cli::Cor20Header;
use crate::formats::cli::StorageHeader;
use crate::formats::cli::StorageSignature;
use crate::formats::cli::StreamHeader;
use crate::formats::cli::MetadataTable;
use crate::formats::cli::Entry;
use crate::formats::cli::MetadataToken;
use crate::formats::cli::MethodDefEntry;
use crate::formats::cli::MethodHeader;
use crate::formats::cli::ModuleEntry;
use crate::formats::cli::TypeRefEntry;
use crate::formats::cli::FieldEntry;
use crate::formats::cli::TinyHeader;
use crate::formats::cli::FatHeader;
use crate::formats::cli::TypeDefEntry;

/// Represents a PE (Portable Executable) file, encapsulating the `lief::pe::Binary` and associated metadata.
pub struct PE {
    pe: lief::pe::Binary,
    pub file: File,
    pub config: Config,
}

impl PE {
    /// Creates a new `PE` instance by reading a PE file from the provided path.
    ///
    /// # Parameters
    /// - `path`: The file path to the PE file to be loaded.
    ///
    /// # Returns
    /// A `Result` containing the `PE` object on success or an `Error` on failure.
    pub fn new(path: String, config: Config) -> Result<Self, Error> {
        let mut file = File::new(path.clone(), config.clone())?;
        match file.read() {
            Ok(_) => (),
            Err(_) => {
                return Err(Error::new(ErrorKind::InvalidInput, "failed to read file"));
            }
        };
        if let Some(Binary::PE(pe)) = Binary::parse(&path) {
            return Ok(Self {
                pe: pe,
                file: file,
                config: config,
            });
        }
        return Err(Error::new(ErrorKind::InvalidInput, "invalid pe file"));
    }

    /// Converts a relative virtual address to a file offset
    ///
    /// # Returns
    /// The file offset as a `Option<u64>`.
    pub fn relative_virtual_address_to_file_offset(&self, rva: u64) -> Option<u64> {
        for section in self.pe.sections() {
            let section_start_rva = section.virtual_address() as u64;
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
    fn dotnet_parse_cor20_header(&self) -> Option<(u64, &Cor20Header)> {
        if !self.is_dotnet() { return None; }
        if let Some(clr_runtime_header) = self.pe.data_directory_by_type(DATA_DIRECTORY::CLR_RUNTIME_HEADER) {
            if let Some(start) = self.relative_virtual_address_to_file_offset(clr_runtime_header.rva() as u64) {
                let end = start + clr_runtime_header.size() as u64;
                let data = &self.file.data[start as usize..end as usize];
                let header = &Cor20Header::from_bytes(&data)?;
                return Some((start, header));
            }
        }
        None
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
    pub fn dotnet_cor20_header(&self) -> Option<&Cor20Header> {
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
    fn dotnet_parse_storage_signature(&self) -> Option<(u64, &StorageSignature)> {
        if !self.is_dotnet() { return None; }
        let (_, image_cor20_header) = self.dotnet_parse_cor20_header()?;
        let rva = image_cor20_header.meta_data.virtual_address as u64;
        let start = self.relative_virtual_address_to_file_offset(rva)? as usize;
        let end = start + StorageSignature::size();
        let data = &self.file.data[start..end];
        let header = StorageSignature::from_bytes(&data)?;
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
    pub fn dotnet_storage_signature(&self) -> Option<&StorageSignature> {
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
    fn dotnet_parse_storage_header(&self) -> Option<(u64, &StorageHeader)> {
        if !self.is_dotnet() { return None; };
        let (mut start, cor20_storage_signaure_header) = self.dotnet_parse_storage_signature()?;
        start += StorageSignature::size() as u64;
        start += cor20_storage_signaure_header.version_string_size as u64;
        start -= 4 as u64;
        let end = start as usize + StorageHeader::size() as usize;
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
    pub fn dotnet_storage_header(&self) -> Option<&StorageHeader> {
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
    fn dotnet_parse_stream_headers(&self) -> Option<BTreeMap<u64, &StreamHeader>> {
        if !self.is_dotnet() { return None; }
        let (cor20_storage_header_offset, cor20_storage_header) = self.dotnet_parse_storage_header()?;
        let mut offset = cor20_storage_header_offset as usize + StorageHeader::size();
        let mut result = BTreeMap::<u64, &StreamHeader>::new();
        for _ in 0.. cor20_storage_header.number_of_streams {
            let data = &self.file.data[offset..offset + StreamHeader::size()];
            let header = StreamHeader::from_bytes(data)?;
            result.insert(offset as u64, header);
            offset += StreamHeader::size() + header.name().len();
        }
        if result.len() <= 0 {
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
    pub fn dotnet_stream_headers(&self) -> Vec<&StreamHeader> {
        let mut result = Vec::<&StreamHeader>::new();
        let headers = self.dotnet_parse_stream_headers();
        if headers.is_none() { return result; }
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
    fn dotnet_parse_metadata_table(&self) -> Option<(u64, &MetadataTable)> {
        if !self.is_dotnet() { return None; }
        let (mut start, _) = self.dotnet_parse_storage_signature()?;
        for (_, header) in self.dotnet_parse_stream_headers()? {
            if header.name() == vec![0x23, 0x7e, 0x00, 0x00] {
                start += header.offset as u64;
            }
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
    pub fn dotnet_metadata_table(&self) -> Option<&MetadataTable> {
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
        if !self.is_dotnet() { return None; }

        let (cor20_metadata_table_offset, cor20_metadata_table) = self.dotnet_parse_metadata_table()?;

        let mut offset: usize = cor20_metadata_table_offset as usize
            + MetadataTable::size()
            + cor20_metadata_table.mask_valid.count_ones() as usize * 4;

        let mut valid_index: usize = 0;

        let mut entries = Vec::<Entry>::new();

        for i in 0..64 as usize {

            let entry_offset = cor20_metadata_table_offset as usize
                + MetadataTable::size()
                + (valid_index * 4);

            if entry_offset + 4 > self.file.data.len() {
                return None;
            }

            let entry_count = u32::from_le_bytes(
                self.file.data[entry_offset..entry_offset + 4].try_into().unwrap(),
            ) as usize;

            match i {
                x if x == MetadataToken::Module as usize => {
                    for _ in 0..entry_count {
                        let entry = ModuleEntry::from_bytes(
                            &self.file.data[offset..],
                            cor20_metadata_table.heap_sizes)?;
                        offset += entry.size();
                        entries.push(Entry::Module(entry));
                    }
                    valid_index += 1;
                }
                x if x == MetadataToken::TypeRef as usize => {
                    for _ in 0..entry_count {
                        let entry = TypeRefEntry::from_bytes(
                            &self.file.data[offset..],
                            cor20_metadata_table.heap_sizes)?;
                        offset += entry.size();
                        entries.push(Entry::TypeRef(entry));
                    }
                    valid_index += 1;
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
                    valid_index += 1;
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
                    valid_index += 1;
                }
                x if x == MetadataToken::MethodDef as usize => {
                    for _ in 0..entry_count {
                        let entry = MethodDefEntry::from_bytes(
                            &self.file.data[offset..],
                            cor20_metadata_table.heap_sizes)?;
                        offset += entry.size();
                        entries.push(Entry::MethodDef(entry));
                    }
                }
                _ => {}
            }
        }

        Some(entries)
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
    pub fn virtual_address_to_relative_virtual_address(&self, address: u64) -> u64{
        address - self.imagebase()
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

        if offset.is_none() { return Err(Error::new(ErrorKind::InvalidInput, "failed to convert virtual address to file offset")); }

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
        return Err(Error::new(ErrorKind::InvalidData, "invalid method header"));
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
        self.pe.imports().any(|import| {
            matches!(import.name().to_lowercase().as_str(), "mscorelib.dll" | "mscoree.dll")
                && self.pe.data_directory_by_type(DATA_DIRECTORY::CLR_RUNTIME_HEADER).is_some()
        })
    }

    /// Creates a new `PE` instance from a byte vector containing PE file data.
    ///
    /// # Parameters
    /// - `bytes`: A vector of bytes representing the PE file data.
    ///
    /// # Returns
    /// A `Result` containing the `PE` object on success or an `Error` on failure.
    #[allow(dead_code)]
    pub fn from_bytes(bytes: Vec<u8>, config: Config) -> Result<Self, Error> {
        let file = File::from_bytes(bytes, config.clone());
        let mut cursor = Cursor::new(&file.data);
        if let Some(Binary::PE(pe)) = Binary::from(&mut cursor) {
            return Ok(Self{
                pe: pe,
                file: file,
                config: config,
            })
        }
        return Err(Error::new(ErrorKind::InvalidInput, "invalid pe file"));
    }

    /// Returns the architecture of the PE file based on its machine type.
    ///
    /// # Returns
    /// The `BinaryArchitecture` enum value corresponding to the PE machine type (e.g., AMD64, I386, CIL or UNKNOWN).
    #[allow(dead_code)]
    pub fn architecture(&self) -> Architecture {
        match self.pe.header().machine() {
            MachineType::I386 if self.is_dotnet() => Architecture::CIL,
            MachineType::I386 => Architecture::I386,
            MachineType::AMD64 => Architecture::AMD64,
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
        if !self.is_dotnet() { return result; }
        let entries = match self.dotnet_metadata_table_entries() {
            Some(entries) => entries,
            None => return result,
        };

        for entry in entries {
            let Entry::MethodDef(entry) = entry else { continue };

            if entry.rva == 0 {
                continue;
            }

            let va = self.relative_virtual_address_to_virtual_address(entry.rva as u64);

            let header = match self.dotnet_method_header(va).ok() {
                Some(header) => header,
                None => continue,
            };

            let header_size = match header.size() {
                Some(size) => size,
                None => continue,
            };

            let code_size = match header.code_size() {
                Some(size) => size,
                None => continue,
            };

            result.insert( va + header_size as u64, va + header_size as u64 + code_size as u64);
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
    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        if self.is_dotnet() { return result; }
        for section in self.pe.sections() {
            if (section.characteristics().bits() & u64::from(Characteristics::MEM_EXECUTE)) == 0 { continue; }
            if section.virtual_size() == 0 { continue; }
            if section.sizeof_raw_data() == 0 { continue; }
            let section_virtual_adddress = PE::align_section_virtual_address(
                self.imagebase() + section.pointerto_raw_data() as u64,
                self.section_alignment(),
                self.file_alignment());
            result.insert(
                section_virtual_adddress,
                section_virtual_adddress + section.virtual_size() as u64);
        }
        return result;
    }

    /// Returns a map of Pogo (debug) entries found in the PE file, keyed by their start RVA (Relative Virtual Address).
    ///
    /// # Returns
    /// A `HashMap` where the key is the RVA of the start of the Pogo entry and the value is the name of the entry.
    #[allow(dead_code)]
    pub fn pogos(&self) -> HashMap<u64, String> {
        let mut result = HashMap::<u64, String>::new();
        for entry in self.pe.debug() {
            match entry {
                Entries::Pogo(pogos) => {
                    for pogo in pogos.entries() {
                        result.insert(self.imagebase() + pogo.start_rva() as u64, pogo.name());
                    }
                },
                _ => {}
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
    pub fn tlscallbacks(&self) -> BTreeSet<u64> {
        self.pe.tls()
            .into_iter()
            .flat_map(|tls| tls.callbacks())
            .collect()
    }

    /// Returns a set of dotnet function virtual addresses in the PE file.
    ///
    /// # Returns
    /// A `BTreeSet` of function addresses in the PE file.
    pub fn dotnet_entrypoints(&self) -> BTreeSet<u64> {
        let mut addresses = BTreeSet::<u64>::new();
        if !self.is_dotnet() { return addresses; }
        let entries = match self.dotnet_metadata_table_entries() {
            Some(entries) => entries,
            None => {
                return addresses;
            },
        };
        for entry in entries {
            match entry {
                Entry::MethodDef(header) => {
                    if header.rva <= 0 { continue; }
                    let mut va = self.relative_virtual_address_to_virtual_address(header.rva as u64);
                    let method_header = match self.dotnet_method_header(va) {
                        Ok(method_header) => method_header,
                        Err(_) => {
                            continue;
                        }
                    };
                    if method_header.size().is_none() {
                        continue;
                    }
                    va += method_header.size().unwrap() as u64;
                    addresses.insert(va);

                },
                _ => {},
            };
        }
        return addresses;
    }

    /// Returns a set of function addresses (entry point, exports, TLS callbacks, and Pogo entries) in the PE file.
    ///
    /// # Returns
    /// A `BTreeSet` of function addresses in the PE file.
    #[allow(dead_code)]
    pub fn entrypoints(&self) -> BTreeSet<u64> {
        let mut addresses = BTreeSet::<u64>::new();
        addresses.insert(self.entrypoint());
        addresses.extend(self.exports());
        addresses.extend(self.tlscallbacks());
        addresses.extend(self.pogos().keys().cloned());
        return addresses;
    }

    /// Returns the entry point address of the PE file.
    ///
    /// # Returns
    /// The entry point address as a `u64` value.
    #[allow(dead_code)]
    pub fn entrypoint(&self) -> u64 {
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
    pub fn align_section_virtual_address(value: u64, mut section_alignment: u64, file_alignment: u64) -> u64 {
        if section_alignment < 0x1000 {
            section_alignment = file_alignment;
        }
        if section_alignment != 0 && (value % section_alignment) != 0 {
            return section_alignment * ((value + section_alignment - 1) / section_alignment);
        }
        return value;
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
    pub fn relative_virtual_address_to_virtual_address(&self, relative_virtual_address: u64) -> u64 {
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
            if file_offset >= section_raw_data_offset && file_offset < section_raw_data_offset + section_raw_data_size {
                let section_virtual_address = self.imagebase() + section.pointerto_raw_data() as u64;
                let section_offset = file_offset - section_raw_data_offset;
                let virtual_address = section_virtual_address + section_offset;
                return Some(virtual_address);
            }
        }
        None
    }

    /// Caches the PE file contents and returns a `MemoryMappedFile` object.
    ///
    /// # Parameters
    /// - `path`: The base path to store the memory mapped file.
    /// - `cache`: Whether to cache the file or not.
    ///
    /// # Returns
    /// A `Result` containing the `MemoryMappedFile` object on success or an `Error` on failure.
    pub fn image(&self) -> Result<MemoryMappedFile, Error> {
        let pathbuf = PathBuf::from(self.config.mmap.directory.clone())
            .join(self.file.sha256_no_config().unwrap());
        let mut tempmap = match MemoryMappedFile::new(pathbuf, self.config.mmap.cache.enabled) {
            Ok(tempmmap) => tempmmap,
            Err(error) => return Err(error),
        };
        if tempmap.is_cached() {
            return Ok(tempmap);
        }
        tempmap.seek_to_end()?;
        tempmap.write(&self.file.data[0..self.sizeofheaders() as usize]).map_err(|error| Error::new(
            ErrorKind::Other,
            format!(
                "failed to write headers to memory-mapped pe file: {}",
                error
            )
        ))?;
        for section in self.pe.sections() {
            if section.virtual_size() == 0 { continue; }
            if section.sizeof_raw_data() == 0 { continue; }
            let section_virtual_adddress = PE::align_section_virtual_address(
                self.imagebase() + section.pointerto_raw_data() as u64,
                self.section_alignment(),
                self.file_alignment());
            if section_virtual_adddress > tempmap.size().unwrap() as u64 {
                let padding_length = section_virtual_adddress - tempmap.size().unwrap() as u64;
                tempmap.seek_to_end()?;
                tempmap.write_padding(padding_length as usize).map_err(|error| Error::new(
                    ErrorKind::Other,
                    format!(
                        "write padding to pe memory-mapped pe file: {}",
                        error
                    )
                ))?;
            }
            let pointerto_raw_data = section.pointerto_raw_data() as usize;
            let sizeof_raw_data = section.sizeof_raw_data() as usize;
            tempmap.seek_to_end()?;
            tempmap.write(&self.file.data[pointerto_raw_data..pointerto_raw_data + sizeof_raw_data]).map_err(|error| Error::new(
                ErrorKind::Other,
                format!(
                    "failed to write section to memory-mapped pe file: {}",
                    error
                )
            ))?;
        }
        Ok(tempmap)
    }

    /// Returns the size of the PE file.
    ///
    /// # Returns
    /// The size of the file as a `u64`.
    #[allow(dead_code)]
    pub fn size(&self) -> u64 {
        self.file.size()
    }

    /// Returns the TLS (Thread Local Storage) hash value if present in the PE file.
    ///
    /// # Returns
    /// An `Option<String>` containing the TLS hash if present, otherwise `None`.
    #[allow(dead_code)]
    pub fn tlsh(&self) -> Option<String> {
        self.file.tlsh()
    }

    /// Returns the SHA-256 hash value of the PE file.
    ///
    /// # Returns
    /// An `Option<String>` containing the SHA-256 hash if available, otherwise `None`.
    #[allow(dead_code)]
    pub fn sha256(&self) -> Option<String> {
        self.file.sha256()
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
    pub fn exports(&self) -> BTreeSet<u64> {
        let mut addresses = BTreeSet::<u64>::new();
        let export = match self.pe.export(){
            Some(export) => export,
            None => {
                return addresses;
            }
        };
        for entry in export.entries(){
            let address = entry.address() as u64 + self.imagebase();
            addresses.insert(address);
        }
        return addresses;
    }
}
