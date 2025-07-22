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

use crate::controlflow::Graph;
use crate::controlflow::Instruction as CFGInstruction;
use crate::disassemblers::custom::cil::Instruction;
use crate::io::Stderr;
use crate::Architecture;
use crate::Config;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;
use std::io::ErrorKind;

pub struct Disassembler<'disassembler> {
    pub architecture: Architecture,
    pub metadata_token_addresses: BTreeMap<u64, u64>,
    pub executable_address_ranges: BTreeMap<u64, u64>,
    pub image: &'disassembler [u8],
    config: Config,
}

impl<'disassembler> Disassembler<'disassembler> {
    pub fn new(
        architecture: Architecture,
        image: &'disassembler [u8],
        metadata_token_addresses: BTreeMap<u64, u64>,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Config,
    ) -> Result<Self, Error> {
        match architecture {
            Architecture::CIL => {}
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "unsupported architecture",
                ));
            }
        }
        Ok(Self {
            architecture,
            metadata_token_addresses,
            executable_address_ranges,
            image,
            config,
        })
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.executable_address_ranges
            .iter()
            .any(|(start, end)| address >= *start && address <= *end)
    }

    fn get_instruction_functions(&self, instruction: &Instruction) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        let call_metadata_token = instruction.get_call_metadata_token();
        if call_metadata_token.is_none() {
            return result;
        }
        let call_address = self
            .metadata_token_addresses
            .get(&(call_metadata_token.unwrap() as u64));
        if call_address.is_none() {
            return result;
        }
        result.insert(*call_address.unwrap());
        result
    }

    pub fn disassemble_instruction(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        cfg.instructions.insert_processed(address);

        if !self.is_executable_address(address) {
            cfg.instructions.insert_invalid(address);
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("0x{:x}: instruction address is not executable", address),
            ));
        }

        let instruction = match Instruction::new(&self.image[address as usize..], address) {
            Ok(instruction) => instruction,
            Err(_) => {
                cfg.instructions.insert_invalid(address);
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("0x{:x}: failed to disassemble instruction", address),
                ));
            }
        };

        let mut cfginstruction =
            CFGInstruction::create(address, self.architecture, cfg.config.clone());

        cfginstruction.bytes = instruction.bytes();
        cfginstruction.is_call = instruction.is_call();
        cfginstruction.is_jump = instruction.is_jump();
        cfginstruction.is_conditional = instruction.is_conditional_jump();
        cfginstruction.is_return = instruction.is_return();
        cfginstruction.is_trap = false;
        cfginstruction.pattern = instruction.pattern();
        cfginstruction.edges = instruction.edges();
        cfginstruction.to = instruction.to();
        cfginstruction.functions = self.get_instruction_functions(&instruction);

        Stderr::print_debug(
            cfg.config.clone(),
            format!(
                "0x{:x}: mnemonic: {:?}, mnemonic_size: {}, operand_size: {}, operand_bytes: {:?}, bytes: {:?}, next: {:?}, to: {:?}, blocks: {:?}",
                instruction.address,
                instruction.mnemonic,
                instruction.mnemonic_size(),
                instruction.operand_size(),
                instruction.operand_bytes(),
                instruction.bytes(),
                instruction.next(),
                instruction.to(),
                cfginstruction.blocks(),
            )
        );

        cfg.insert_instruction(cfginstruction);

        cfg.instructions.insert_valid(address);

        Ok(address)
    }

    pub fn disassemble_block(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        cfg.blocks.insert_processed(address);

        if !self.is_executable_address(address) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("0x{:x}: block address is not executable", address),
            ));
        }

        let mut pc = address;

        loop {
            if let Err(error) = self.disassemble_instruction(pc, cfg) {
                cfg.blocks.insert_invalid(address);
                return Err(error);
            }

            let mut instruction = match cfg.get_instruction(pc) {
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

    pub fn disassemble_function(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
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
                .disassemble_block(block_start_address, cfg)
                .inspect_err(|_| {
                    cfg.functions.insert_invalid(address);
                })?;

            if block_start_address == address {
                if let Some(mut instruction) = cfg.get_instruction(block_start_address) {
                    instruction.is_function_start = true;
                    cfg.update_instruction(instruction);
                }
            }

            if let Some(instruction) = cfg.get_instruction(block_end_address) {
                cfg.blocks.enqueue_extend(instruction.blocks());
            }
        }

        cfg.functions.insert_valid(address);

        Ok(address)
    }

    pub fn disassemble_controlflow<'a>(
        &'a self,
        addresses: BTreeSet<u64>,
        cfg: &'a mut Graph,
    ) -> Result<(), Error> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(cfg.config.general.threads)
            .build()
            .map_err(|error| Error::other(format!("{}", error)))?;

        cfg.functions.enqueue_extend(addresses);

        let external_image = self.image;

        let external_machine = self.architecture;

        let external_executable_address_ranges = self.executable_address_ranges.clone();

        let external_metadata_token_addresses = self.metadata_token_addresses.clone();

        let external_config = self.config.clone();

        pool.install(|| {
            while !cfg.functions.queue.is_empty() {
                let function_addresses = cfg.functions.dequeue_all();
                cfg.functions
                    .insert_processed_extend(function_addresses.clone());
                let graphs: Vec<Graph> = function_addresses
                    .par_iter()
                    .map(|address| {
                        let machine = external_machine;
                        let executable_address_ranges = external_executable_address_ranges.clone();
                        let metadata_token_addresses = external_metadata_token_addresses.clone();
                        let image = external_image;
                        let mut graph = Graph::new(machine, cfg.config.clone());
                        if let Ok(disasm) = Disassembler::new(
                            machine,
                            image,
                            metadata_token_addresses,
                            executable_address_ranges,
                            external_config.clone(),
                        ) {
                            let _ = disasm.disassemble_function(*address, &mut graph);
                        }
                        graph
                    })
                    .collect();
                for mut graph in graphs {
                    cfg.absorb(&mut graph);
                }
            }
        });

        Ok(())
    }
}
