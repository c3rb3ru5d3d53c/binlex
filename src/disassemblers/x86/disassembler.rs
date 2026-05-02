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
use crate::controlflow::Instruction;
use crate::disassemblers::x86::classify as x86_classify;
use crate::disassemblers::x86::pattern::{
    X86PatternOperand, X86PatternOperandKind, displacement_size_bits, instruction_chromosome_mask,
    is_immutable_instruction_to_pattern, is_unsupported_pattern_mnemonic,
};
use crate::disassemblers::x86::{
    prologue as x86_prologue, sweep as x86_sweep, translate as x86_translate,
};
use crate::io::Stderr;
use ::capstone::Insn;
use ::capstone::Instructions;
use ::capstone::arch::ArchOperand;
use ::capstone::arch::x86::X86OperandType;
use ::capstone::prelude::*;
use rayon::ThreadPoolBuilder;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Capstone,
}

pub struct Disassembler<'a> {
    pub(crate) cs: Capstone,
    pub(crate) machine: Architecture,
    pub(crate) image: &'a [u8],
    executable_address_ranges: BTreeMap<u64, u64>,
    pub(crate) config: Configuration,
    selected_backend: Backend,
}

impl<'a> Disassembler<'a> {
    pub fn new(
        machine: Architecture,
        image: &'a [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::with_backend(
            Backend::Capstone,
            machine,
            image,
            executable_address_ranges,
            config,
        )
    }

    pub fn with_backend(
        backend: Backend,
        machine: Architecture,
        image: &'a [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        let cs = match backend {
            Backend::Capstone => Self::cs_new(machine, true)?,
        };
        Ok(Self {
            cs,
            machine,
            image,
            executable_address_ranges,
            config,
            selected_backend: backend,
        })
    }

    pub fn disassemble_instruction(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        cfg.instructions.insert_processed(address);

        if let Some(instruction) = cfg.get_instruction(address) {
            return Ok(instruction.address);
        }

        if !self.is_executable_address(address) {
            cfg.instructions.insert_invalid(address);
            let error = format!(
                "Instruction -> 0x{:x}: it is not in executable memory",
                address
            );
            Stderr::print_debug(&cfg.config, error.clone());
            return Err(Error::new(ErrorKind::Other, error));
        }

        let instruction = self
            .prepare_instruction(self.machine, address, cfg)
            .map_err(|_| {
                cfg.instructions.insert_invalid(address);
                let error = format!("0x{:x}: failed to disassemble instruction", address);
                Error::new(ErrorKind::Other, error)
            })?;

        Stderr::print_debug(
            &cfg.config,
            format!(
                "0x{:x}: mnemonic: {:?}, next: {:?}, to: {:?}, is_conditional: {:?}, is_jump: {:?}",
                instruction.address,
                instruction.mnemonic,
                instruction.next(),
                instruction.to(),
                instruction.is_conditional,
                instruction.is_jump,
            ),
        );

        cfg.functions.enqueue_extend(instruction.functions.clone());
        cfg.insert_instruction(instruction);
        cfg.instructions.insert_valid(address);

        Ok(address)
    }

    fn is_function_prologue(&self, address: u64) -> bool {
        let Ok(instructions) = self.disassemble_instructions(address, 2) else {
            return false;
        };
        if instructions.len() < 2 {
            return false;
        }
        if instructions[0].mnemonic().unwrap_or("") != "push"
            || instructions[1].mnemonic().unwrap_or("") != "mov"
        {
            return false;
        }
        x86_prologue::is_function_prologue(self.machine, |instruction_index, operand_index| {
            self.decode_instruction_operand(&instructions[instruction_index], operand_index)
        })
    }

    pub fn disassemble_block(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        cfg.blocks.insert_processed(address);

        if !self.is_executable_address(address) {
            cfg.functions.insert_invalid(address);
            return Err(Error::new(
                ErrorKind::Other,
                format!("Block -> 0x{:x}: it is not in executable memory", address),
            ));
        }

        let mut pc = address;
        let mut has_prologue = false;
        let mut terminator = address;
        let mut split_successor: Option<u64> = None;

        while self.disassemble_instruction(pc, cfg).is_ok() {
            let mut instruction = match cfg.get_instruction(pc) {
                Some(instr) => instr,
                None => {
                    cfg.blocks.insert_invalid(address);
                    return Err(Error::new(
                        ErrorKind::Other,
                        "failed to disassemble instruction",
                    ));
                }
            };

            if instruction.address == address {
                instruction.is_block_start = true;
                cfg.update_instruction(instruction.clone());
            }

            if instruction.address == address && instruction.is_block_start {
                instruction.is_prologue = self.is_function_prologue(instruction.address);
                has_prologue = instruction.is_prologue;
                cfg.update_instruction(instruction.clone());
            }

            let is_block_start = instruction.address != address && instruction.is_block_start;

            if is_block_start {
                split_successor = Some(instruction.address);
                break;
            }

            terminator = instruction.address;

            if instruction.is_trap || instruction.is_return || instruction.is_jump {
                break;
            }

            pc += instruction.size() as u64;

            if cfg.blocks.is_pending(pc) || cfg.blocks.is_processed(pc) || cfg.blocks.is_valid(pc) {
                split_successor = Some(pc);
                break;
            }
        }

        if let Some(successor) = split_successor {
            cfg.extend_instruction_edges(terminator, BTreeSet::from([successor]));
        }

        if has_prologue {
            cfg.functions.enqueue(address);
        }
        cfg.blocks.insert_valid(address);

        Ok(terminator)
    }

    pub fn disassemble_function(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        if !self.is_executable_address(address) {
            cfg.functions.insert_invalid(address);
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Function -> 0x{:x}: it is not in executable memory",
                    address
                ),
            ));
        }

        cfg.functions.insert_processed(address);
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

    pub fn disassemble(&self, addresses: BTreeSet<u64>, cfg: &mut Graph) -> Result<(), Error> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(cfg.config.resolved_threads())
            .build()
            .map_err(|error| Error::new(ErrorKind::Other, format!("{}", error)))?;

        if cfg.config.disassembler.sweep.enabled {
            cfg.functions.enqueue_extend(self.disassemble_sweep());
        }

        cfg.functions.enqueue_extend(addresses);

        let external_image = self.image;
        let external_machine = self.machine;
        let external_executable_address_ranges = self.executable_address_ranges.clone();
        let external_config = self.config.clone();
        let graph_config = cfg.config.clone();
        let selected_backend = self.selected_backend;

        pool.install(|| {
            while !cfg.functions.queue.is_empty() {
                let function_addresses = cfg.functions.dequeue_all();
                cfg.functions
                    .insert_processed_extend(function_addresses.clone());
                let function_groups: Vec<Vec<u64>> = function_addresses
                    .iter()
                    .copied()
                    .collect::<Vec<_>>()
                    .chunks(cfg.config.resolved_threads().max(1))
                    .map(|chunk| chunk.to_vec())
                    .collect();
                let graphs: Vec<Graph> = function_groups
                    .par_iter()
                    .map_init(
                        || {
                            Disassembler::with_backend(
                                selected_backend,
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
                                    let _ = disasm.disassemble_function(*address, &mut graph);
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

    pub fn disassemble_sweep(&self) -> BTreeSet<u64> {
        x86_sweep::disassemble(
            self.machine,
            &self.executable_address_ranges,
            &self.config,
            |address, graph| self.prepare_instruction(self.machine, address, graph),
            |address| self.is_executable_address(address),
        )
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.executable_address_ranges
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    pub(crate) fn prepare_instruction(
        &self,
        machine: Architecture,
        address: u64,
        cfg: &Graph,
    ) -> Result<Instruction, Error> {
        x86_translate::build_instruction(self, machine, address, cfg)
    }

    pub fn get_instruction_chromosome_mask(&self, instruction: &Insn) -> Result<Vec<u8>, Error> {
        let operands = self.get_instruction_operands(instruction)?;
        let decoded_operands = operands
            .iter()
            .filter_map(|operand| self.decode_history_operand(operand))
            .collect::<Vec<_>>();
        let pattern_operands = operands
            .iter()
            .filter_map(|operand| match operand {
                ArchOperand::X86Operand(op) => Some(X86PatternOperand {
                    operand_size_bits: (op.size as usize) * 8,
                    displacement_size_bits: match op.op_type {
                        X86OperandType::Mem(op_mem) => {
                            displacement_size_bits(op_mem.disp().unsigned_abs())
                        }
                        _ => 0,
                    },
                    kind: match op.op_type {
                        X86OperandType::Imm(_) => X86PatternOperandKind::Immediate,
                        X86OperandType::Mem(mem) if mem.index() == RegId(0) => {
                            X86PatternOperandKind::MemoryNoIndex
                        }
                        X86OperandType::Mem(_) => X86PatternOperandKind::MemoryWithIndex,
                        _ => X86PatternOperandKind::Other,
                    },
                }),
                _ => None,
            })
            .collect::<Vec<_>>();

        instruction_chromosome_mask(
            instruction.address(),
            instruction.bytes(),
            instruction.mnemonic().unwrap_or(""),
            Self::is_wildcard_instruction(instruction),
            &pattern_operands,
            &decoded_operands,
        )
    }

    #[allow(dead_code)]
    pub fn print_instructions(instructions: &Instructions) {
        for instruction in instructions.iter() {
            Self::print_instruction(instruction);
        }
    }

    #[allow(dead_code)]
    pub fn is_immutable_instruction_to_pattern(&self, instruction: &Insn) -> bool {
        let raw_operands = match self.get_instruction_operands(instruction) {
            Ok(operands) => operands,
            Err(_) => return false,
        };
        let operands = raw_operands
            .iter()
            .filter_map(|operand| self.decode_history_operand(operand))
            .collect::<Vec<_>>();
        is_immutable_instruction_to_pattern(instruction.mnemonic().unwrap_or(""), &operands)
    }

    #[allow(dead_code)]
    pub fn is_unsupported_pattern_instruction(instruction: &Insn) -> bool {
        is_unsupported_pattern_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_return_instruction(insn: &Insn) -> bool {
        x86_classify::is_return_mnemonic(insn.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_privilege_instruction(instruction: &Insn) -> bool {
        x86_classify::is_privilege_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_wildcard_instruction(instruction: &Insn) -> bool {
        x86_classify::is_wildcard_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_nop_instruction(instruction: &Insn) -> bool {
        x86_classify::is_nop_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_trap_instruction(instruction: &Insn) -> bool {
        x86_classify::is_trap_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_jump_instruction(instruction: &Insn) -> bool {
        x86_classify::is_jump_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_load_address_instruction(instruction: &Insn) -> bool {
        x86_classify::is_load_address_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_call_instruction(instruction: &Insn) -> bool {
        x86_classify::is_call_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_unconditional_jump_instruction(instruction: &Insn) -> bool {
        x86_classify::is_unconditional_jump_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    #[allow(dead_code)]
    pub fn is_conditional_jump_instruction(instruction: &Insn) -> bool {
        x86_classify::is_conditional_jump_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn print_instruction(instruction: &Insn) {
        println!(
            "0x{:x}: {} {} {}",
            instruction.address(),
            instruction
                .bytes()
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<_>>()
                .join(" "),
            instruction.mnemonic().unwrap_or(""),
            instruction.op_str().unwrap_or(""),
        );
    }
}
