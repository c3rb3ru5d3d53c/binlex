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
use crate::controlflow::Graph;
use crate::disassemblers::capstone::x86::Disassembler as X86Disassembler;
use crate::Architecture;
use crate::Config;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind};

pub trait ArchDisassembler {
    fn disassemble_instruction(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error>;
    fn disassemble_block(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error>;
    fn disassemble_function(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error>;
    fn disassemble_controlflow(
        &self,
        addresses: BTreeSet<u64>,
        cfg: &mut Graph,
    ) -> Result<(), Error>;
    fn disassemble_sweep(&self) -> BTreeSet<u64>;
}

pub enum DisassemblerBackend<'a> {
    X86(X86Disassembler<'a>),
}

impl ArchDisassembler for DisassemblerBackend<'_> {
    fn disassemble_sweep(&self) -> BTreeSet<u64> {
        match self {
            DisassemblerBackend::X86(d) => d.disassemble_sweep(),
        }
    }
    fn disassemble_instruction(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        match self {
            DisassemblerBackend::X86(d) => d.disassemble_instruction(address, cfg),
        }
    }

    fn disassemble_block(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        match self {
            DisassemblerBackend::X86(d) => d.disassemble_block(address, cfg),
        }
    }

    fn disassemble_function(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        match self {
            DisassemblerBackend::X86(d) => d.disassemble_function(address, cfg),
        }
    }

    fn disassemble_controlflow(
        &self,
        addresses: BTreeSet<u64>,
        cfg: &mut Graph,
    ) -> Result<(), Error> {
        match self {
            DisassemblerBackend::X86(d) => d.disassemble_controlflow(addresses, cfg),
        }
    }
}

pub struct Disassembler<'a> {
    backend: DisassemblerBackend<'a>,
}

impl<'a> Disassembler<'a> {
    pub fn new(
        machine: Architecture,
        image: &'a [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Config,
    ) -> Result<Self, Error> {
        let backend = match machine {
            Architecture::AMD64 | Architecture::I386 => {
                let disasm = X86Disassembler::new(
                    machine,
                    image,
                    executable_address_ranges.clone(),
                    config.clone(),
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

    pub fn disassemble_instruction(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        self.backend.disassemble_instruction(address, cfg)
    }

    pub fn disassemble_block(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        self.backend.disassemble_block(address, cfg)
    }

    pub fn disassemble_function(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        self.backend.disassemble_function(address, cfg)
    }

    pub fn disassemble_controlflow(
        &self,
        addresses: BTreeSet<u64>,
        cfg: &mut Graph,
    ) -> Result<(), Error> {
        self.backend.disassemble_controlflow(addresses, cfg)
    }

    pub fn disassemble_sweep(&self) -> BTreeSet<u64> {
        self.backend.disassemble_sweep()
    }
}
