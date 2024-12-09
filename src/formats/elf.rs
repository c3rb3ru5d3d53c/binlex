use lief::generic::{Section, Symbol};
use lief::Binary;
use lief::elf::segment::Type as SegmentType;
use std::io::{Cursor, Error, ErrorKind};
use std::collections::BTreeSet;
use std::path::PathBuf;
use crate::Architecture;
use crate::formats::File;
use std::collections::BTreeMap;
use crate::types::MemoryMappedFile;
use lief::elf::section::Flags;
use crate::Config;
use lief::elf::symbol::Type as ElfSymbolType;
use crate::controlflow::Symbol as BlSymbol;

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
            return Ok(Self {
                elf: elf,
                file: file,
                config: config,
            });
        }
        return Err(Error::new(ErrorKind::InvalidInput, "invalid elf file"));
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
            return Ok(Self{
                elf: elf,
                file: file,
                config: config,
            })
        }
        return Err(Error::new(ErrorKind::InvalidInput, "invalid elf file"));
    }

    pub fn architecture(&self) -> Architecture {
        let architecture = match self.elf.header().machine_type() {
            62 => Architecture::AMD64,
            3 => Architecture::I386,
            _ => Architecture::UNKNOWN,
        };
        architecture
    }

    pub fn entrypoint(&self) -> u64 {
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

    pub fn exports(&self) -> BTreeSet<u64> {
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
                (self.imagebase() + symbol.value()) as u64,
                BlSymbol {
                    symbol_type: "function".to_string(),
                    name: symbol.name(),
                    address: self.imagebase() + symbol.value(),
                },
            )
        })
        .collect()
    }

    pub fn relative_virtual_address_to_virtual_address(&self, relative_virtual_address: u64) -> u64 {
        self.imagebase() + relative_virtual_address
    }

    pub fn file_offset_to_virtual_address(&self, file_offset: u64) -> Option<u64> {
        for segment in self.elf.segments() {
            let start = segment.file_offset();
            let end = start + segment.physical_size();
            if file_offset >= start && file_offset < end {
                let segment_virtual_address = self.imagebase() + segment.virtual_address();
                return Some(segment_virtual_address + (file_offset - start))
            }
        }
        None
    }

    pub fn image(&self) -> Result<MemoryMappedFile, Error> {
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

        tempmap.seek_to_end()?;
        tempmap.write(&self.file.data[0..self.elf.header().header_size() as usize])?;

        for segment in self.elf.segments() {
            let segment_virtual_address = self.imagebase() + segment.virtual_address();

            if segment_virtual_address > tempmap.size()? as u64 {
                let padding_length = segment_virtual_address - tempmap.size()? as u64;
                tempmap.seek_to_end()?;
                tempmap.write_padding(padding_length as usize)?;
            }

            if segment.p_type() == SegmentType::LOAD {
                let segment_file_offset = segment.file_offset() as usize;
                let segment_size = segment.physical_size() as usize;

                if segment_file_offset + segment_size <= self.file.data.len() {
                    tempmap.seek_to_end()?;
                    tempmap.write(&self.file.data[segment_file_offset..segment_file_offset + segment_size])?;
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

    pub fn entrypoints(&self) -> BTreeSet<u64> {
        let mut entrypoints = BTreeSet::<u64>::new();
        entrypoints.insert(self.entrypoint());
        entrypoints.extend(self.exports());
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
