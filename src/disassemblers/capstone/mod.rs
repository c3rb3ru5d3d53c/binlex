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

extern crate capstone;

use crate::Architecture;
use crate::Configuration;
use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::disassemblers::arm64::Disassembler as Arm64Disassembler;
use crate::disassemblers::x86::Disassembler as X86Disassembler;
use crate::formats::Image;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind};

pub mod arm64;
pub mod x86;

pub trait ArchDisassembler {
    fn disassemble_instruction_address(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error>;
    fn disassemble_block_address(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error>;
    fn disassemble_function_address(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error>;
    fn disassemble(&self, addresses: BTreeSet<u64>, cfg: &mut Graph) -> Result<(), Error>;
    fn disassemble_sweep(&self) -> BTreeSet<u64>;
}

pub enum DisassemblerBackend<'a> {
    Arm64(Arm64Disassembler<'a>),
    X86(X86Disassembler<'a>),
}

impl ArchDisassembler for DisassemblerBackend<'_> {
    fn disassemble_sweep(&self) -> BTreeSet<u64> {
        match self {
            DisassemblerBackend::Arm64(d) => d.disassemble_sweep(),
            DisassemblerBackend::X86(d) => d.disassemble_sweep(),
        }
    }

    fn disassemble_instruction_address(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        match self {
            DisassemblerBackend::Arm64(d) => d.disassemble_instruction_address(address, cfg),
            DisassemblerBackend::X86(d) => d.disassemble_instruction_address(address, cfg),
        }
    }

    fn disassemble_block_address(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        match self {
            DisassemblerBackend::Arm64(d) => d.disassemble_block_address(address, cfg),
            DisassemblerBackend::X86(d) => d.disassemble_block_address(address, cfg),
        }
    }

    fn disassemble_function_address(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        match self {
            DisassemblerBackend::Arm64(d) => d.disassemble_function_address(address, cfg),
            DisassemblerBackend::X86(d) => d.disassemble_function_address(address, cfg),
        }
    }

    fn disassemble(&self, addresses: BTreeSet<u64>, cfg: &mut Graph) -> Result<(), Error> {
        match self {
            DisassemblerBackend::Arm64(d) => d.disassemble(addresses, cfg),
            DisassemblerBackend::X86(d) => d.disassemble(addresses, cfg),
        }
    }
}

pub struct Disassembler<'a> {
    backend: DisassemblerBackend<'a>,
}

impl<'a> Disassembler<'a> {
    pub fn from_image(
        machine: Architecture,
        image: &'a mut Image,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        let image_base = image.base();
        let bytes = image.mmap()?;
        Self::new_with_image_base(
            machine,
            bytes,
            image_base,
            executable_address_ranges,
            config,
        )
    }

    pub fn from_bytes(
        machine: Architecture,
        bytes: &'a [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::new(machine, bytes, executable_address_ranges, config)
    }

    pub fn new(
        machine: Architecture,
        image: &'a [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::new_with_image_base(machine, image, 0, executable_address_ranges, config)
    }

    pub fn new_with_image_base(
        machine: Architecture,
        image: &'a [u8],
        image_base: u64,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        let backend = match machine {
            Architecture::ARM64 => {
                let disasm = Arm64Disassembler::new_with_image_base(
                    machine,
                    image,
                    image_base,
                    executable_address_ranges.clone(),
                    config,
                )
                .map_err(|_| Error::other("failed to create ARM64 disassembler"))?;
                DisassemblerBackend::Arm64(disasm)
            }
            Architecture::AMD64 | Architecture::I386 => {
                let disasm = X86Disassembler::new_with_image_base(
                    machine,
                    image,
                    image_base,
                    executable_address_ranges.clone(),
                    config,
                )
                .map_err(|_| Error::other("failed to create X86 disassembler"))?;
                DisassemblerBackend::X86(disasm)
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "unsupported architecture",
                ));
            }
        };

        Ok(Self { backend })
    }

    pub fn disassemble_instruction<'b>(
        &self,
        address: u64,
        cfg: &'b mut Graph,
    ) -> Result<Instruction<'b>, Error> {
        let entry = self.disassemble_instruction_address(address, cfg)?;
        cfg.get_instruction(entry).ok_or_else(|| {
            Error::other(format!(
                "0x{entry:x}: instruction missing after disassembly"
            ))
        })
    }

    pub fn disassemble_instruction_address(
        &self,
        address: u64,
        cfg: &mut Graph,
    ) -> Result<u64, Error> {
        self.backend.disassemble_instruction_address(address, cfg)
    }

    pub fn disassemble_block<'b>(
        &self,
        address: u64,
        cfg: &'b mut Graph,
    ) -> Result<Block<'b>, Error> {
        self.disassemble_block_address(address, cfg)?;
        cfg.get_block(address)
            .ok_or_else(|| Error::other(format!("0x{address:x}: block missing after disassembly")))
    }

    pub fn disassemble_block_address(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        self.backend.disassemble_block_address(address, cfg)
    }

    pub fn disassemble_function<'b>(
        &self,
        address: u64,
        cfg: &'b mut Graph,
    ) -> Result<Function<'b>, Error> {
        self.disassemble_function_address(address, cfg)?;
        cfg.get_function(address).ok_or_else(|| {
            Error::other(format!("0x{address:x}: function missing after disassembly"))
        })
    }

    pub fn disassemble_function_address(
        &self,
        address: u64,
        cfg: &mut Graph,
    ) -> Result<u64, Error> {
        self.backend.disassemble_function_address(address, cfg)
    }

    pub fn disassemble(&self, addresses: BTreeSet<u64>, cfg: &mut Graph) -> Result<(), Error> {
        self.backend.disassemble(addresses, cfg)
    }

    pub fn disassemble_sweep(&self) -> BTreeSet<u64> {
        self.backend.disassemble_sweep()
    }
}
