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
use crate::controlflow::Graph;
use crate::controlflow::{Block, Function, Instruction};
use crate::formats::Image;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind};

pub mod arm64;
pub mod capstone;
pub mod cil;
pub mod x86;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisassemblerBackend {
    Default,
    Capstone,
    Native,
}

enum DisassemblerImpl<'a> {
    X86(x86::Disassembler<'a>),
    Arm64(arm64::Disassembler<'a>),
    Cil(cil::Disassembler<'a>),
}

pub struct Disassembler<'a> {
    inner: DisassemblerImpl<'a>,
}

fn parse_metadata_address(value: &str) -> Option<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    value.parse::<u64>().ok()
}

fn cil_metadata_token_addresses(cfg: &Graph) -> BTreeMap<u64, u64> {
    let metadata = cfg.metadata();
    let Some(Value::Object(cil)) = metadata.get("cil") else {
        return BTreeMap::new();
    };
    let Some(Value::Object(tokens)) = cil.get("metadata_token_virtual_addresses") else {
        return BTreeMap::new();
    };
    tokens
        .iter()
        .filter_map(|(token, address)| Some((parse_metadata_address(token)?, address.as_u64()?)))
        .collect()
}

impl<'a> Disassembler<'a> {
    pub fn from_image(
        architecture: Architecture,
        _image: &'a Image,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        let _ = (architecture, executable_address_ranges, config);
        Err(Error::other(
            "image-backed disassembler construction requires graph/image decoding support",
        ))
    }

    pub fn from_bytes(
        architecture: Architecture,
        bytes: &'a [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::new(architecture, bytes, executable_address_ranges, config)
    }

    pub fn new(
        architecture: Architecture,
        image: &'a [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::new_with_image_base(architecture, image, 0, executable_address_ranges, config)
    }

    pub fn new_with_image_base(
        architecture: Architecture,
        image: &'a [u8],
        image_base: u64,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::new_with_backend(
            DisassemblerBackend::Default,
            architecture,
            image,
            image_base,
            executable_address_ranges,
            config,
        )
    }

    pub fn new_with_backend(
        backend: DisassemblerBackend,
        architecture: Architecture,
        image: &'a [u8],
        image_base: u64,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        let inner = match (architecture, backend) {
            (Architecture::UNKNOWN, _) => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "unknown architecture is unsupported",
                ));
            }
            (Architecture::AMD64 | Architecture::I386, DisassemblerBackend::Default)
            | (Architecture::AMD64 | Architecture::I386, DisassemblerBackend::Capstone) => {
                DisassemblerImpl::X86(x86::Disassembler::with_backend(
                    x86::disassembler::Backend::Capstone,
                    architecture,
                    image,
                    image_base,
                    executable_address_ranges,
                    config,
                )?)
            }
            (Architecture::ARM64, DisassemblerBackend::Default)
            | (Architecture::ARM64, DisassemblerBackend::Capstone) => {
                DisassemblerImpl::Arm64(arm64::Disassembler::with_backend(
                    arm64::disassembler::Backend::Capstone,
                    architecture,
                    image,
                    image_base,
                    executable_address_ranges,
                    config,
                )?)
            }
            (Architecture::CIL, DisassemblerBackend::Default)
            | (Architecture::CIL, DisassemblerBackend::Native) => {
                DisassemblerImpl::Cil(cil::Disassembler::with_backend(
                    cil::disassembler::Backend::Native,
                    architecture,
                    image,
                    image_base,
                    executable_address_ranges,
                    config,
                )?)
            }
            (Architecture::CIL, DisassemblerBackend::Capstone) => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "capstone backend is unsupported for cil",
                ));
            }
            (_, DisassemblerBackend::Native) => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "native backend is unsupported for this architecture",
                ));
            }
        };

        Ok(Self { inner })
    }

    pub fn disassemble_instruction<'g>(
        &self,
        address: u64,
        cfg: &'g mut Graph,
    ) -> Result<Instruction<'g>, Error> {
        match &self.inner {
            DisassemblerImpl::X86(disassembler) => {
                disassembler.disassemble_instruction(address, cfg)
            }
            DisassemblerImpl::Arm64(disassembler) => {
                disassembler.disassemble_instruction(address, cfg)
            }
            DisassemblerImpl::Cil(disassembler) => {
                let metadata_token_addresses = cil_metadata_token_addresses(cfg);
                disassembler.disassemble_instruction(address, &metadata_token_addresses, cfg)
            }
        }
    }

    pub fn disassemble_block<'g>(
        &self,
        address: u64,
        cfg: &'g mut Graph,
    ) -> Result<Block<'g>, Error> {
        match &self.inner {
            DisassemblerImpl::X86(disassembler) => disassembler.disassemble_block(address, cfg),
            DisassemblerImpl::Arm64(disassembler) => disassembler.disassemble_block(address, cfg),
            DisassemblerImpl::Cil(disassembler) => {
                let metadata_token_addresses = cil_metadata_token_addresses(cfg);
                disassembler.disassemble_block(address, &metadata_token_addresses, cfg)
            }
        }
    }

    pub fn disassemble_function<'g>(
        &self,
        address: u64,
        cfg: &'g mut Graph,
    ) -> Result<Function<'g>, Error> {
        match &self.inner {
            DisassemblerImpl::X86(disassembler) => disassembler.disassemble_function(address, cfg),
            DisassemblerImpl::Arm64(disassembler) => {
                disassembler.disassemble_function(address, cfg)
            }
            DisassemblerImpl::Cil(disassembler) => {
                let metadata_token_addresses = cil_metadata_token_addresses(cfg);
                disassembler.disassemble_function(address, &metadata_token_addresses, cfg)
            }
        }
    }

    pub fn disassemble(&self, addresses: BTreeSet<u64>, cfg: &mut Graph) -> Result<(), Error> {
        match &self.inner {
            DisassemblerImpl::X86(disassembler) => disassembler.disassemble(addresses, cfg),
            DisassemblerImpl::Arm64(disassembler) => disassembler.disassemble(addresses, cfg),
            DisassemblerImpl::Cil(disassembler) => {
                let metadata_token_addresses = cil_metadata_token_addresses(cfg);
                disassembler.disassemble(addresses, metadata_token_addresses, cfg)
            }
        }
    }

    pub fn disassemble_sweep(&self) -> BTreeSet<u64> {
        match &self.inner {
            DisassemblerImpl::X86(disassembler) => disassembler.disassemble_sweep(),
            DisassemblerImpl::Arm64(disassembler) => disassembler.disassemble_sweep(),
            DisassemblerImpl::Cil(_) => BTreeSet::new(),
        }
    }
}
