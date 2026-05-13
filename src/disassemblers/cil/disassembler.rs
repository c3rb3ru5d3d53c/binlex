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
use crate::controlflow::Instruction as CFGInstruction;
use crate::controlflow::InstructionDetail;
use crate::controlflow::{Block, Function, Graph, Instruction as ControlFlowInstruction};
use crate::disassemblers::cil::Instruction;
use crate::disassemblers::cil::backends::native;
use crate::genetics::Chromosome;
use crate::io::Stderr;
use crate::semantics::cil::InstructionDetailCil;
use rayon::ThreadPoolBuilder;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Native,
}

pub struct Disassembler<'disassembler> {
    pub architecture: Architecture,
    pub executable_address_ranges: BTreeMap<u64, u64>,
    pub image: &'disassembler [u8],
    pub image_base: u64,
    config: Configuration,
}

impl<'disassembler> Disassembler<'disassembler> {
    const FUNCTION_GROUP_SIZE: usize = 4;

    pub fn new(
        architecture: Architecture,
        image: &'disassembler [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::new_with_image_base(architecture, image, 0, executable_address_ranges, config)
    }

    pub fn new_with_image_base(
        architecture: Architecture,
        image: &'disassembler [u8],
        image_base: u64,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::with_backend(
            Backend::Native,
            architecture,
            image,
            image_base,
            executable_address_ranges,
            config,
        )
    }

    pub fn with_backend(
        backend: Backend,
        architecture: Architecture,
        image: &'disassembler [u8],
        image_base: u64,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        match backend {
            Backend::Native => {}
        }
        native::validate_architecture(architecture)?;
        Ok(Self {
            architecture,
            executable_address_ranges,
            image,
            image_base,
            config,
        })
    }

    fn image_offset(&self, address: u64) -> Option<usize> {
        address
            .checked_sub(self.image_base)
            .map(|offset| offset as usize)
            .filter(|offset| *offset <= self.image.len())
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.executable_address_ranges
            .iter()
            .any(|(start, end)| address >= *start && address <= *end)
    }

    fn group_function_addresses(addresses: &BTreeSet<u64>) -> Vec<Vec<u64>> {
        let mut groups = Vec::new();
        let mut current = Vec::with_capacity(Self::FUNCTION_GROUP_SIZE);
        for address in addresses {
            current.push(*address);
            if current.len() == Self::FUNCTION_GROUP_SIZE {
                groups.push(current);
                current = Vec::with_capacity(Self::FUNCTION_GROUP_SIZE);
            }
        }
        if !current.is_empty() {
            groups.push(current);
        }
        groups
    }

    fn get_instruction_functions(
        &self,
        instruction: &Instruction,
        metadata_token_addresses: &BTreeMap<u64, u64>,
    ) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        let call_metadata_token = instruction.get_call_metadata_token();
        if call_metadata_token.is_none() {
            return result;
        }
        let call_address = metadata_token_addresses.get(&(call_metadata_token.unwrap() as u64));
        if call_address.is_none() {
            return result;
        }
        result.insert(*call_address.unwrap());
        result
    }

    pub fn disassemble_instruction_address(
        &self,
        address: u64,
        metadata_token_addresses: &BTreeMap<u64, u64>,
        cfg: &mut Graph,
    ) -> Result<u64, Error> {
        cfg.instructions.insert_processed(address);

        if !self.is_executable_address(address) {
            cfg.instructions.insert_invalid(address);
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("0x{:x}: instruction address is not executable", address),
            ));
        }

        let Some(offset) = self.image_offset(address) else {
            cfg.instructions.insert_invalid(address);
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "0x{:x}: instruction address is out of image bounds",
                    address
                ),
            ));
        };

        let instruction = match native::decode_instruction(&self.image[offset..], address) {
            Ok(instruction) => instruction,
            Err(_) => {
                cfg.instructions.insert_invalid(address);
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("0x{:x}: failed to disassemble instruction", address),
                ));
            }
        };
        let semantic_view = InstructionDetailCil::new(
            instruction.mnemonic.name(),
            instruction.address,
            instruction.operand_bytes(),
            instruction.fallthrough(),
            instruction.branches(),
            instruction.is_call(),
            instruction.is_return(),
            instruction.is_jump(),
            instruction.is_conditional_jump(),
            instruction.is_switch(),
        );
        let function_targets =
            self.get_instruction_functions(&instruction, metadata_token_addresses);

        let mut cfginstruction =
            CFGInstruction::create(address, self.architecture, cfg.config.clone());

        cfginstruction.bytes = instruction.bytes();
        cfginstruction.is_call = instruction.is_call();
        cfginstruction.is_jump = instruction.is_jump();
        cfginstruction.is_conditional = instruction.is_conditional_jump();
        cfginstruction.is_return = instruction.is_return();
        cfginstruction.is_trap = false;
        cfginstruction.pattern = instruction.pattern();
        cfginstruction.chromosome_mask =
            Chromosome::from_pattern(cfginstruction.pattern.clone(), cfg.config.clone())
                .expect("failed to parse CIL chromosome pattern")
                .mask();
        cfginstruction.edges = instruction.edges();
        cfginstruction.mnemonic = instruction.mnemonic_text();
        cfginstruction.disassembly = instruction.disassembly_text(metadata_token_addresses);
        cfginstruction.operands = instruction.normalized_operands(metadata_token_addresses);
        cfginstruction.to = instruction.branches();
        cfginstruction.functions = function_targets;
        cfginstruction.set_instruction_detail(InstructionDetail::cil(semantic_view));
        if cfg.config.semantics.enabled {
            cfginstruction.semantics = cfginstruction.build_and_log_semantics();
        }

        Stderr::print_debug(
            &cfg.config,
            format!(
                "0x{:x}: mnemonic: {:?}, mnemonic_size: {}, operand_size: {}, operand_bytes: {:?}, bytes: {:?}, fallthrough: {:?}, branches: {:?}, successor_blocks: {:?}",
                instruction.address,
                instruction.mnemonic,
                instruction.mnemonic_size(),
                instruction.operand_size(),
                instruction.operand_bytes(),
                instruction.bytes(),
                instruction.fallthrough(),
                instruction.branches(),
                cfginstruction.successor_block_references(),
            ),
        );

        cfg.insert_instruction(cfginstruction);

        cfg.instructions.insert_valid(address);

        Ok(address)
    }

    pub fn disassemble_block_address(
        &self,
        address: u64,
        metadata_token_addresses: &BTreeMap<u64, u64>,
        cfg: &mut Graph,
    ) -> Result<u64, Error> {
        cfg.blocks.insert_processed(address);

        if !self.is_executable_address(address) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("0x{:x}: block address is not executable", address),
            ));
        }

        let mut pc = address;

        loop {
            if let Err(error) =
                self.disassemble_instruction_address(pc, metadata_token_addresses, cfg)
            {
                cfg.blocks.insert_invalid(address);
                return Err(error);
            }

            let mut instruction = match cfg.get_instruction_record(pc) {
                Some(instruction) => instruction,
                None => {
                    cfg.blocks.insert_invalid(address);
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("0x{:x}: failed to disassemble instruction", pc),
                    ));
                }
            };

            if instruction.address == address {
                instruction.is_block_start = true;
                cfg.update_instruction(instruction.clone());
            }

            let is_block_start = instruction.address != address && instruction.is_block_start;

            if instruction.is_trap || instruction.is_return || instruction.is_jump || is_block_start
            {
                break;
            }

            pc += instruction.size() as u64;
        }

        cfg.blocks.insert_valid(address);

        Ok(pc)
    }

    pub fn disassemble_function_address(
        &self,
        address: u64,
        metadata_token_addresses: &BTreeMap<u64, u64>,
        cfg: &mut Graph,
    ) -> Result<u64, Error> {
        cfg.functions.insert_processed(address);

        if !self.is_executable_address(address) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("0x{:x}: function address is not executable", address),
            ));
        }

        cfg.blocks.enqueue(address);

        while let Some(block_start_address) = cfg.blocks.dequeue() {
            if cfg.blocks.is_processed(block_start_address) {
                continue;
            }

            let block_end_address = self
                .disassemble_block_address(block_start_address, metadata_token_addresses, cfg)
                .inspect_err(|_| {
                    cfg.functions.insert_invalid(address);
                })?;

            if block_start_address == address {
                if let Some(mut instruction) = cfg.get_instruction_record(block_start_address) {
                    instruction.is_function_start = true;
                    cfg.update_instruction(instruction);
                }
            }

            if let Some(instruction) = cfg.get_instruction(block_end_address) {
                cfg.blocks.enqueue_extend(instruction.successors());
            }
        }

        cfg.functions.insert_valid(address);

        Ok(address)
    }

    pub fn disassemble_instruction<'a>(
        &self,
        address: u64,
        metadata_token_addresses: &BTreeMap<u64, u64>,
        cfg: &'a mut Graph,
    ) -> Result<ControlFlowInstruction<'a>, Error> {
        let entry = self.disassemble_instruction_address(address, metadata_token_addresses, cfg)?;
        cfg.get_instruction(entry).ok_or_else(|| {
            Error::other(format!(
                "0x{entry:x}: instruction missing after disassembly"
            ))
        })
    }

    pub fn disassemble_block<'a>(
        &self,
        address: u64,
        metadata_token_addresses: &BTreeMap<u64, u64>,
        cfg: &'a mut Graph,
    ) -> Result<Block<'a>, Error> {
        self.disassemble_block_address(address, metadata_token_addresses, cfg)?;
        cfg.get_block(address)
            .ok_or_else(|| Error::other(format!("0x{address:x}: block missing after disassembly")))
    }

    pub fn disassemble_function<'a>(
        &self,
        address: u64,
        metadata_token_addresses: &BTreeMap<u64, u64>,
        cfg: &'a mut Graph,
    ) -> Result<Function<'a>, Error> {
        self.disassemble_function_address(address, metadata_token_addresses, cfg)?;
        cfg.get_function(address).ok_or_else(|| {
            Error::other(format!("0x{address:x}: function missing after disassembly"))
        })
    }

    pub fn disassemble<'a>(
        &'a self,
        addresses: BTreeSet<u64>,
        metadata_token_addresses: BTreeMap<u64, u64>,
        cfg: &'a mut Graph,
    ) -> Result<(), Error> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(cfg.config.resolved_threads())
            .build()
            .map_err(|error| Error::other(format!("{}", error)))?;

        cfg.functions.enqueue_extend(addresses);

        let external_image = self.image;
        let external_machine = self.architecture;
        let external_executable_address_ranges = self.executable_address_ranges.clone();
        let external_config = self.config.clone();
        let graph_config = cfg.config.clone();

        pool.install(|| {
            while !cfg.functions.queue.is_empty() {
                let function_addresses = cfg.functions.dequeue_all();
                cfg.functions
                    .insert_processed_extend(function_addresses.clone());
                let function_groups = Self::group_function_addresses(&function_addresses);
                let graphs: Vec<Graph> = function_groups
                    .par_iter()
                    .map_init(
                        || {
                            Disassembler::new(
                                external_machine,
                                external_image,
                                external_executable_address_ranges.clone(),
                                external_config.clone(),
                            )
                            .ok()
                        },
                        |disasm, addresses| {
                            let mut graph = Graph::new(external_machine, graph_config.clone());
                            if let Some(disasm) = disasm.as_ref() {
                                for address in addresses {
                                    let _ = disasm.disassemble_function(
                                        *address,
                                        &metadata_token_addresses,
                                        &mut graph,
                                    );
                                }
                            }
                            graph
                        },
                    )
                    .collect();
                for mut graph in graphs {
                    cfg.merge(&mut graph);
                }
            }
        });

        Ok(())
    }
}
