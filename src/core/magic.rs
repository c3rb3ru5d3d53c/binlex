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

use std::fmt;
use std::io::Error;
use std::io::ErrorKind;
use std::str::FromStr;

#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Magic {
    /// Raw File
    CODE = 0x00,
    /// Portable Executable
    PE = 0x01,
    /// COFF Object
    COFF = 0x06,
    /// ELF Executable
    ELF = 0x02,
    /// MachO Executable
    MACHO = 0x03,
    /// PNG Image
    PNG = 0x04,
    /// Unknown formats
    UNKNOWN = 0x05,
}

impl Magic {
    pub fn new(bytes: &[u8]) -> Magic {
        if Self::is_pe(bytes) {
            return Magic::PE;
        }

        if Self::is_coff(bytes) {
            return Magic::COFF;
        }

        if Self::is_elf(bytes) {
            return Magic::ELF;
        }

        if Self::is_macho(bytes) {
            return Magic::MACHO;
        }

        if Self::is_png(bytes) {
            return Magic::PNG;
        }

        Magic::UNKNOWN
    }

    fn is_pe(bytes: &[u8]) -> bool {
        if !bytes.starts_with(&[0x4d, 0x5a]) {
            return false;
        }

        let Some(pe_offset_bytes) = bytes.get(0x3c..0x40) else {
            return false;
        };

        let pe_offset = u32::from_le_bytes([
            pe_offset_bytes[0],
            pe_offset_bytes[1],
            pe_offset_bytes[2],
            pe_offset_bytes[3],
        ]) as usize;

        bytes
            .get(pe_offset..pe_offset + 4)
            .is_some_and(|signature| signature == [0x50, 0x45, 0x00, 0x00])
    }

    fn is_elf(bytes: &[u8]) -> bool {
        bytes
            .get(0x01..0x04)
            .is_some_and(|magic| magic == [0x45, 0x4c, 0x46])
    }

    fn is_coff(bytes: &[u8]) -> bool {
        if bytes.len() < 20 {
            return false;
        }
        let machine = u16::from_le_bytes([bytes[0], bytes[1]]);
        if !matches!(machine, 0x014c | 0x8664 | 0xAA64) {
            return false;
        }
        let number_of_sections = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        if number_of_sections == 0 {
            return false;
        }
        let size_of_optional_header = u16::from_le_bytes([bytes[16], bytes[17]]) as usize;
        let section_table_offset = 20usize.saturating_add(size_of_optional_header);
        let section_table_size = match number_of_sections.checked_mul(40) {
            Some(size) => size,
            None => return false,
        };
        let section_table_end = match section_table_offset.checked_add(section_table_size) {
            Some(end) => end,
            None => return false,
        };
        section_table_end <= bytes.len()
    }

    fn is_macho(bytes: &[u8]) -> bool {
        bytes.get(0x00..0x04).is_some_and(|magic| {
            magic == [0xCE, 0xFA, 0xED, 0xFE]
                || magic == [0xCF, 0xFA, 0xED, 0xFE]
                || magic == [0xBE, 0xBA, 0xFE, 0xCA]
        })
    }

    fn is_png(bytes: &[u8]) -> bool {
        bytes.starts_with(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    }
}

impl fmt::Display for Magic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let format: &str = match self {
            Magic::CODE => "code",
            Magic::PE => "pe",
            Magic::COFF => "coff",
            Magic::ELF => "elf",
            Magic::MACHO => "macho",
            Magic::PNG => "png",
            Magic::UNKNOWN => "unknown",
        };
        write!(f, "{}", format)
    }
}

#[cfg(test)]
mod tests {
    use super::Magic;

    #[test]
    fn detects_pe_from_bytes() {
        let mut bytes = vec![0u8; 0x44];
        bytes[0] = 0x4d;
        bytes[1] = 0x5a;
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);

        assert_eq!(Magic::new(&bytes), Magic::PE);
    }

    #[test]
    fn detects_coff_from_bytes() {
        let mut bytes = vec![0u8; 60];
        bytes[0..2].copy_from_slice(&0x14cu16.to_le_bytes());
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());

        assert_eq!(Magic::new(&bytes), Magic::COFF);
    }

    #[test]
    fn detects_elf_from_bytes() {
        let bytes = [0x7f, 0x45, 0x4c, 0x46];

        assert_eq!(Magic::new(&bytes), Magic::ELF);
    }

    #[test]
    fn detects_macho_from_bytes() {
        let bytes = [0xCF, 0xFA, 0xED, 0xFE];

        assert_eq!(Magic::new(&bytes), Magic::MACHO);
    }

    #[test]
    fn detects_png_from_bytes() {
        let bytes = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

        assert_eq!(Magic::new(&bytes), Magic::PNG);
    }

    #[test]
    fn returns_unknown_for_short_or_unrecognized_bytes() {
        assert_eq!(Magic::new(&[]), Magic::UNKNOWN);
        assert_eq!(Magic::new(&[0x4d, 0x5a]), Magic::UNKNOWN);
        assert_eq!(Magic::new(&[0x00, 0x01, 0x02, 0x03]), Magic::UNKNOWN);
    }
}

impl FromStr for Magic {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "code" => Ok(Magic::CODE),
            "pe" => Ok(Magic::PE),
            "coff" => Ok(Magic::COFF),
            "elf" => Ok(Magic::ELF),
            "macho" => Ok(Magic::MACHO),
            "png" => Ok(Magic::PNG),
            "unknown" => Ok(Magic::UNKNOWN),
            _ => Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid format: '{}'", s),
            )),
        }
    }
}
