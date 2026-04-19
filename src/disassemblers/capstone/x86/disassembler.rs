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
use crate::Config;
use crate::controlflow::graph::Graph;
use crate::controlflow::instruction::Instruction;
use crate::genetics::Chromosome;
use crate::io::Stderr;
use crate::semantics;
use crate::semantics::InstructionSemantics;
use crate::semantics::SemanticStatus;
use arch::x86::X86OpMem;
use arch::x86::X86Reg::{X86_REG_EBP, X86_REG_ESP, X86_REG_RBP, X86_REG_RIP, X86_REG_RSP};
use capstone::Insn;
use capstone::InsnId;
use capstone::Instructions;
use capstone::arch::ArchOperand;
use capstone::arch::x86::X86Insn;
use capstone::arch::x86::X86OperandType;
use capstone::prelude::*;
use rayon::ThreadPoolBuilder;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Error;
use std::io::ErrorKind;

#[derive(Clone)]
struct DecodedInstruction {
    address: u64,
    id: InsnId,
    bytes: Vec<u8>,
    operands: Vec<ArchOperand>,
}

pub struct Disassembler<'disassembler> {
    cs: Capstone,
    image: &'disassembler [u8],
    machine: Architecture,
    executable_address_ranges: BTreeMap<u64, u64>,
    config: Config,
}

impl<'disassembler> Disassembler<'disassembler> {
    const FUNCTION_GROUP_SIZE: usize = 4;

    fn log_semantics_debug(&self, semantics: &InstructionSemantics, instruction: &Insn) {
        if semantics.status == SemanticStatus::Complete && semantics.diagnostics.is_empty() {
            return;
        }

        let summary = if semantics.diagnostics.is_empty() {
            format!(
                "no diagnostics; mnemonic={}; effects={}; terminator={:?}",
                instruction.mnemonic().unwrap_or("unknown"),
                semantics.effects.len(),
                semantics.terminator.kind()
            )
        } else {
            semantics
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        };

        Stderr::print_debug(
            &self.config,
            format!(
                "0x{:x}: semantics status={:?}, diagnostics={}",
                instruction.address(),
                semantics.status,
                summary
            ),
        );
    }

    pub fn new(
        machine: Architecture,
        image: &'disassembler [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Config,
    ) -> Result<Self, Error> {
        let cs = Disassembler::cs_new(machine, true)?;
        Ok(Self {
            cs,
            image,
            machine,
            executable_address_ranges,
            config,
        })
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

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.executable_address_ranges
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    #[allow(dead_code)]
    pub fn disassemble_sweep(&self) -> BTreeSet<u64> {
        let valid_jump_threshold: usize = 2;
        let valid_instruction_threshold: usize = 4;

        let mut functions = BTreeSet::<u64>::new();
        for (start, end) in self.executable_address_ranges.clone() {
            let mut pc = start;
            let mut valid_instructions = 0;
            let mut valid_jumps = 0;
            while pc < end {
                let instructions = match self.disassemble_instructions(pc, 1) {
                    Ok(instructions) => instructions,
                    Err(_) => {
                        pc += 1;
                        valid_instructions = 0;
                        valid_jumps = 0;
                        continue;
                    }
                };
                let instruction = instructions.iter().next().unwrap();
                if Disassembler::is_privilege_instruction(instruction)
                    || Disassembler::is_trap_instruction(instruction)
                {
                    pc += instruction.bytes().len() as u64;
                    continue;
                }
                if let Some(imm) = self.get_jump_immutable(instruction) {
                    if self.is_executable_address(imm) {
                        valid_jumps += 1;
                    } else {
                        valid_instructions = 0;
                        valid_jumps = 0;
                        pc += 1;
                        continue;
                    }
                }
                if let Some(imm) = self.get_call_immutable(instruction) {
                    if valid_jumps >= valid_jump_threshold
                        && valid_instructions >= valid_instruction_threshold
                    {
                        if self.is_executable_address(imm) {
                            functions.insert(imm);
                        } else {
                            valid_instructions = 0;
                            valid_jumps = 0;
                            pc += 1;
                            continue;
                        }
                    }
                }
                valid_instructions += 1;
                pc += instruction.bytes().len() as u64;
            }
        }
        functions
    }

    #[allow(dead_code)]
    pub fn disassemble<'a>(
        &'a self,
        addresses: BTreeSet<u64>,
        cfg: &'a mut Graph,
    ) -> Result<(), Error> {
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

    pub fn disassemble_function<'a>(
        &'a self,
        address: u64,
        cfg: &'a mut Graph,
    ) -> Result<u64, Error> {
        cfg.functions.insert_processed(address);

        if !self.is_executable_address(address) {
            cfg.functions.insert_invalid(address);
            let error_message = format!(
                "Function -> 0x{:x}: it is not in executable memory",
                address
            );
            Stderr::print_debug(&cfg.config, &error_message);
            return Err(Error::new(ErrorKind::Other, error_message));
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

    pub fn disassemble_instruction<'a>(
        &'a self,
        address: u64,
        cfg: &'a mut Graph,
    ) -> Result<u64, Error> {
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

        let instruction_container = self.disassemble_instructions(address, 1)?;
        let instruction = instruction_container.iter().next().ok_or_else(|| {
            cfg.instructions.insert_invalid(address);
            let error = format!("0x{:x}: failed to disassemble instruction", address);
            Error::new(ErrorKind::Other, error)
        })?;

        let instruction_mask = self.get_instruction_chromosome_mask(instruction)?;
        let instruction_signature = Chromosome::new(
            instruction.bytes().to_vec(),
            instruction_mask.clone(),
            cfg.config.clone(),
        )?
        .pattern();

        let mut blinstruction =
            Instruction::create(instruction.address(), cfg.architecture, cfg.config.clone());

        blinstruction.is_jump = Disassembler::is_jump_instruction(instruction);
        blinstruction.is_call = Disassembler::is_call_instruction(instruction);
        blinstruction.is_return = Disassembler::is_return_instruction(instruction);
        blinstruction.is_trap = Disassembler::is_trap_instruction(instruction);

        if blinstruction.is_jump {
            blinstruction.is_conditional =
                Disassembler::is_conditional_jump_instruction(instruction);
        }

        blinstruction.edges = self.get_instruction_edges(instruction);
        blinstruction.bytes = instruction.bytes().to_vec();
        blinstruction.chromosome_mask = instruction_mask;
        blinstruction.pattern = instruction_signature;
        blinstruction.has_indirect_target = self.has_indirect_controlflow_target(instruction);

        if let Some(addr) = self.get_conditional_jump_immutable(instruction) {
            blinstruction.to.insert(addr);
        }
        if let Some(addr) = self.get_unconditional_jump_immutable(instruction) {
            blinstruction.to.insert(addr);
        }
        if let Some(addr) = self.get_call_immutable(instruction) {
            if self.is_executable_address(addr) {
                cfg.functions.enqueue(addr);
                blinstruction.functions.insert(addr);
            }
        }
        let indirect_targets = self.get_indirect_controlflow_targets(instruction, cfg);
        if blinstruction.is_jump {
            blinstruction.to.extend(indirect_targets.clone());
        }
        if blinstruction.is_call {
            for addr in indirect_targets {
                cfg.functions.enqueue(addr);
                blinstruction.functions.insert(addr);
            }
        }
        if let Some(addr) = self.get_instruction_executable_addresses(instruction) {
            cfg.functions.enqueue(addr);
            blinstruction.functions.insert(addr);
        }

        if blinstruction.is_jump || blinstruction.is_return || blinstruction.is_trap {
            blinstruction.edges = blinstruction.blocks().len();
        }

        if cfg.config.semantics.enabled {
            let operands = self
                .get_instruction_operands(instruction)
                .unwrap_or_default();
            let semantics = semantics::capstone::x86::build(self.machine, instruction, &operands);
            self.log_semantics_debug(&semantics, instruction);
            blinstruction.semantics = Some(semantics);
        }

        Stderr::print_debug(
            &cfg.config,
            format!(
                "0x{:x}: mnemonic: {:?}, next: {:?}, to: {:?}, is_conditional: {:?}, is_jump: {:?}",
                blinstruction.address,
                instruction.mnemonic().unwrap(),
                blinstruction.next(),
                blinstruction.to(),
                blinstruction.is_conditional,
                blinstruction.is_jump,
            ),
        );

        cfg.insert_instruction(blinstruction);

        cfg.instructions.insert_valid(address);

        Ok(address)
    }

    #[allow(dead_code)]
    pub fn disassemble_block<'a>(&'a self, address: u64, cfg: &'a mut Graph) -> Result<u64, Error> {
        cfg.blocks.insert_processed(address);

        if !self.is_executable_address(address) {
            cfg.functions.insert_invalid(address);
            let error_message = format!("Block -> 0x{:x}: it is not in executable memory", address);
            Stderr::print_debug(&cfg.config, error_message.clone());
            return Err(Error::new(ErrorKind::Other, error_message));
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

    pub fn is_function_prologue(&self, address: u64) -> bool {
        // Starting Instructions
        if let Ok(instructions) = self.disassemble_instructions(address, 2) {
            match self.machine {
                Architecture::AMD64 => {
                    if instructions[0].id() == InsnId(X86Insn::X86_INS_PUSH as u32)
                        && self.instruction_has_register_operand(
                            &instructions[0],
                            0,
                            RegId(X86_REG_RBP as u16),
                        )
                        && instructions[1].id() == InsnId(X86Insn::X86_INS_MOV as u32)
                        && self.instruction_has_register_operand(
                            &instructions[1],
                            0,
                            RegId(X86_REG_RBP as u16),
                        )
                        && self.instruction_has_register_operand(
                            &instructions[1],
                            1,
                            RegId(X86_REG_RSP as u16),
                        )
                    {
                        return true;
                    }
                }
                Architecture::I386 => {
                    if instructions[0].id() == InsnId(X86Insn::X86_INS_PUSH as u32)
                        && self.instruction_has_register_operand(
                            &instructions[0],
                            0,
                            RegId(X86_REG_EBP as u16),
                        )
                        && instructions[1].id() == InsnId(X86Insn::X86_INS_MOV as u32)
                        && self.instruction_has_register_operand(
                            &instructions[1],
                            0,
                            RegId(X86_REG_EBP as u16),
                        )
                        && self.instruction_has_register_operand(
                            &instructions[1],
                            1,
                            RegId(X86_REG_ESP as u16),
                        )
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
    }

    fn instruction_has_register_operand(
        &self,
        instruction: &Insn,
        index: usize,
        register_id: RegId,
    ) -> bool {
        let operands = match self.get_instruction_operands(instruction) {
            Ok(operands) => operands,
            Err(_) => return false,
        };

        if let Some(operand) = operands.get(index) {
            if let ArchOperand::X86Operand(op) = operand {
                if let X86OperandType::Reg(reg_id) = op.op_type {
                    return reg_id == register_id;
                }
            }
        }
        false
    }

    #[allow(dead_code)]
    pub fn get_operand_mem(operand: &ArchOperand) -> Option<X86OpMem> {
        if let ArchOperand::X86Operand(operand) = operand {
            if let X86OperandType::Mem(_operand) = operand.op_type {
                return Some(_operand);
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_instruction_total_operand_size(&self, instruction: &Insn) -> Result<usize, Error> {
        let operands = self.get_instruction_operands(instruction)?;
        Disassembler::get_total_operand_size(&operands)
    }

    pub fn instruction_contains_memory_operand(&self, instruction: &Insn) -> bool {
        let operands = match self.get_instruction_operands(instruction) {
            Ok(operands) => operands,
            Err(_) => return false,
        };
        for operand in operands {
            if let ArchOperand::X86Operand(op) = operand {
                match op.op_type {
                    X86OperandType::Mem(_) => return true,
                    _ => continue,
                };
            }
        }
        false
    }

    pub fn instruction_contains_immutable_operand(&self, instruction: &Insn) -> bool {
        let operands = match self.get_instruction_operands(instruction) {
            Ok(operands) => operands,
            Err(_) => return false,
        };
        for operand in operands {
            if let ArchOperand::X86Operand(op) = operand {
                match op.op_type {
                    X86OperandType::Imm(_) => return true,
                    _ => continue,
                };
            }
        }
        false
    }

    fn get_total_operand_size(operands: &[ArchOperand]) -> Result<usize, Error> {
        let mut result: usize = 0;
        for operand in operands {
            match operand {
                ArchOperand::X86Operand(op) => {
                    result += op.size as usize;
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "unsupported operand architecture",
                    ));
                }
            }
        }
        Ok(result)
    }

    fn is_immutable_instruction_to_pattern_with_operands(
        instruction: &Insn,
        operands: &[ArchOperand],
        has_immutable_operand: bool,
    ) -> bool {
        if !has_immutable_operand {
            return false;
        }

        if Disassembler::is_call_instruction(instruction)
            || Disassembler::is_jump_instruction(instruction)
        {
            return true;
        }

        const STACK_INSTRUCTIONS: [InsnId; 5] = [
            InsnId(X86Insn::X86_INS_MOV as u32),
            InsnId(X86Insn::X86_INS_SUB as u32),
            InsnId(X86Insn::X86_INS_ADD as u32),
            InsnId(X86Insn::X86_INS_INC as u32),
            InsnId(X86Insn::X86_INS_DEC as u32),
        ];

        if STACK_INSTRUCTIONS.contains(&instruction.id()) {
            for operand in operands {
                if let ArchOperand::X86Operand(op) = operand {
                    if let X86OperandType::Reg(register_id) = op.op_type {
                        if [X86_REG_RSP, X86_REG_RBP, X86_REG_ESP, X86_REG_EBP]
                            .contains(&(register_id.0 as u32))
                        {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    #[allow(dead_code)]
    pub fn get_instruction_pattern(&self, instruction: &Insn) -> Result<String, Error> {
        let mask = self.get_instruction_chromosome_mask(instruction)?;
        Chromosome::new(instruction.bytes().to_vec(), mask, self.config.clone())
            .map(|c| c.pattern())
    }

    pub fn get_instruction_chromosome_mask(&self, instruction: &Insn) -> Result<Vec<u8>, Error> {
        if Disassembler::is_unsupported_pattern_instruction(instruction) {
            return Ok(vec![0; instruction.bytes().len()]);
        }

        if Disassembler::is_wildcard_instruction(instruction) {
            return Ok(vec![0xFF; instruction.bytes().len()]);
        }

        let operands = self.get_instruction_operands(instruction)?;
        let has_immutable_operand = operands.iter().any(|operand| {
            matches!(
                operand,
                ArchOperand::X86Operand(op) if matches!(op.op_type, X86OperandType::Imm(_))
            )
        });
        let has_memory_operand = operands.iter().any(|operand| {
            matches!(
                operand,
                ArchOperand::X86Operand(op) if matches!(op.op_type, X86OperandType::Mem(_))
            )
        });

        if !has_immutable_operand && !has_memory_operand {
            return Ok(vec![0; instruction.bytes().len()]);
        }

        let instruction_size_bits = instruction.bytes().len() * 8;

        let mut wildcarded = vec![false; instruction_size_bits];

        let instruction_trailing_null_size_bits = instruction
            .bytes()
            .iter()
            .rev()
            .take_while(|&&b| b == 0)
            .count()
            * 8;

        let total_operand_size_bits = Disassembler::get_total_operand_size(&operands)? * 8;

        if total_operand_size_bits > instruction_size_bits {
            return Ok(vec![0; instruction.bytes().len()]);
        }

        let is_immutable_signature =
            Disassembler::is_immutable_instruction_to_pattern_with_operands(
                instruction,
                &operands,
                has_immutable_operand,
            );

        if total_operand_size_bits == 0 && !operands.is_empty() {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Instruction -> 0x{:x}: instruction has operands but missing operand sizes",
                    instruction.address()
                ),
            ));
        }

        for operand in operands {
            if let ArchOperand::X86Operand(op) = operand {
                let should_wildcard = match op.op_type {
                    X86OperandType::Imm(_) => is_immutable_signature,
                    X86OperandType::Mem(mem) => mem.index() == RegId(0),
                    _ => false,
                };

                let displacement_size_bits = match op.op_type {
                    X86OperandType::Mem(op_mem) => {
                        Disassembler::get_displacement_size(op_mem.disp().unsigned_abs()) * 8
                    }
                    _ => 0,
                };

                let operand_size_bits = (op.size as usize) * 8;

                let mut op_size_bits = if operand_size_bits > displacement_size_bits {
                    operand_size_bits
                } else {
                    displacement_size_bits
                };

                if op_size_bits > instruction_size_bits {
                    op_size_bits = operand_size_bits;
                }

                if op_size_bits > instruction_size_bits {
                    Disassembler::print_instruction(instruction);
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Instruction -> 0x{:x}: instruction operand size exceeds instruction size",
                            instruction.address()
                        ),
                    ));
                }

                let operand_offset_bits = instruction_size_bits - op_size_bits;

                if should_wildcard {
                    for i in 0..op_size_bits {
                        if operand_offset_bits + i >= wildcarded.len() {
                            Disassembler::print_instruction(instruction);
                            return Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Instruction -> 0x{:x}: instruction wildcard index is out of bounds",
                                    instruction.address()
                                ),
                            ));
                        }
                        wildcarded[operand_offset_bits + i] = true;
                    }
                }
            }
        }

        let mut mask = vec![0u8; instruction.bytes().len()];
        for (byte_index, chunk) in wildcarded.chunks(8).enumerate() {
            let mut byte_mask = 0u8;
            for (bit_index, wildcarded_bit) in chunk.iter().enumerate() {
                if *wildcarded_bit {
                    byte_mask |= 1 << (7 - bit_index);
                }
            }
            mask[byte_index] = byte_mask;
        }

        if is_immutable_signature && instruction_trailing_null_size_bits > 0 {
            let trailing_start =
                instruction.bytes().len() - (instruction_trailing_null_size_bits / 8);
            for byte_mask in mask.iter_mut().skip(trailing_start) {
                *byte_mask = 0xFF;
            }
        }

        Ok(mask)
    }

    fn get_displacement_size(displacement: u64) -> usize {
        match displacement {
            0x00..=0xFF => 1,
            0x100..=0xFFFF => 2,
            0x10000..=0xFFFFFFFF => 4,
            _ => 8,
        }
    }

    #[allow(dead_code)]
    pub fn get_jump_immutable(&self, instruction: &Insn) -> Option<u64> {
        if Disassembler::is_jump_instruction(instruction) {
            let operand = match self.get_instruction_operand(instruction, 0) {
                Ok(operand) => operand,
                Err(_error) => return None,
            };
            return Disassembler::get_operand_immutable(&operand);
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_conditional_jump_immutable(&self, instruction: &Insn) -> Option<u64> {
        if Disassembler::is_conditional_jump_instruction(instruction) {
            let operand = match self.get_instruction_operand(instruction, 0) {
                Ok(operand) => operand,
                Err(_error) => return None,
            };
            return Disassembler::get_operand_immutable(&operand);
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_unconditional_jump_immutable(&self, instruction: &Insn) -> Option<u64> {
        if Disassembler::is_unconditional_jump_instruction(instruction) {
            let operand = match self.get_instruction_operand(instruction, 0) {
                Ok(operand) => operand,
                Err(_error) => return None,
            };
            return Disassembler::get_operand_immutable(&operand);
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_instruction_executable_addresses(&self, instruction: &Insn) -> Option<u64> {
        if !Disassembler::is_load_address_instruction(instruction) {
            return None;
        }
        let operands = match self.get_instruction_operands(instruction) {
            Ok(operands) => operands,
            Err(_) => return None,
        };
        for operand in operands {
            if let ArchOperand::X86Operand(operand) = operand {
                if let X86OperandType::Mem(mem) = operand.op_type {
                    if mem.index() != RegId(0) {
                        continue;
                    }
                    let address = match self.resolve_memory_operand_address(instruction, mem) {
                        Some(address) => address,
                        None => continue,
                    };
                    if !self.is_executable_address(address) {
                        continue;
                    }
                    return Some(address);
                }
            }
        }
        None
    }

    fn has_indirect_controlflow_target(&self, instruction: &Insn) -> bool {
        if !Disassembler::is_call_instruction(instruction)
            && !Disassembler::is_jump_instruction(instruction)
        {
            return false;
        }
        let operand = match self.get_instruction_operand(instruction, 0) {
            Ok(operand) => operand,
            Err(_) => return false,
        };
        matches!(
            operand,
            ArchOperand::X86Operand(op)
                if matches!(op.op_type, X86OperandType::Reg(_) | X86OperandType::Mem(_))
        )
    }

    fn get_indirect_controlflow_target(&self, instruction: &Insn) -> Option<u64> {
        if !self.has_indirect_controlflow_target(instruction) {
            return None;
        }
        let operand = match self.get_instruction_operand(instruction, 0) {
            Ok(operand) => operand,
            Err(_) => return None,
        };
        if let ArchOperand::X86Operand(op) = operand {
            if let X86OperandType::Mem(mem) = op.op_type {
                return self.resolve_memory_operand_target(instruction, mem);
            }
        }
        None
    }

    fn get_indirect_controlflow_targets(&self, instruction: &Insn, cfg: &Graph) -> BTreeSet<u64> {
        let mut targets = BTreeSet::new();

        if let Some(target) = self.get_indirect_controlflow_target(instruction) {
            targets.insert(target);
        }

        if !Disassembler::is_unconditional_jump_instruction(instruction) {
            return targets;
        }

        let operand = match self.get_instruction_operand(instruction, 0) {
            Ok(operand) => operand,
            Err(_) => return targets,
        };

        let history = self.get_recent_decoded_instructions(instruction.address(), cfg, 6);

        if let ArchOperand::X86Operand(op) = operand {
            match op.op_type {
                X86OperandType::Mem(mem) if mem.index() != RegId(0) => {
                    targets.extend(self.resolve_jump_table_memory_targets(
                        instruction,
                        mem,
                        op.size as usize,
                        &history,
                    ));
                }
                X86OperandType::Reg(reg) => {
                    targets.extend(self.resolve_register_jump_table_targets(reg, &history));
                }
                _ => {}
            }
        }

        targets
    }

    fn get_recent_decoded_instructions(
        &self,
        address: u64,
        cfg: &Graph,
        max_count: usize,
    ) -> Vec<DecodedInstruction> {
        let mut addresses = Vec::new();
        for entry in cfg.listing.range(..address) {
            addresses.push(*entry.key());
        }
        let start = addresses.len().saturating_sub(max_count);
        let mut decoded = Vec::new();
        for address in &addresses[start..] {
            let Ok(insns) = self.disassemble_instructions(*address, 1) else {
                continue;
            };
            let Some(insn) = insns.iter().next() else {
                continue;
            };
            let Ok(operands) = self.get_instruction_operands(insn) else {
                continue;
            };
            decoded.push(DecodedInstruction {
                address: insn.address(),
                id: insn.id(),
                bytes: insn.bytes().to_vec(),
                operands,
            });
        }
        decoded
    }

    fn resolve_jump_table_memory_targets(
        &self,
        instruction: &Insn,
        mem: X86OpMem,
        operand_size: usize,
        history: &[DecodedInstruction],
    ) -> BTreeSet<u64> {
        let mut result = BTreeSet::new();
        let Some(table_base) = self.resolve_jump_table_base(instruction, mem, history) else {
            return result;
        };
        let Some(case_count) = self.find_jump_table_case_count(mem.index(), history) else {
            return result;
        };

        let entry_size = self.get_jump_table_entry_size(mem.scale() as usize, operand_size);
        if entry_size == 0 {
            return result;
        }

        for i in 0..case_count {
            let entry_address = match table_base.checked_add((i * entry_size) as u64) {
                Some(address) => address,
                None => break,
            };
            let Some(target) = self.read_pointer_sized(entry_address, entry_size) else {
                break;
            };
            if !self.is_executable_address(target) {
                break;
            }
            result.insert(target);
        }

        result
    }

    fn resolve_register_jump_table_targets(
        &self,
        jump_register: RegId,
        history: &[DecodedInstruction],
    ) -> BTreeSet<u64> {
        let mut result = BTreeSet::new();
        if history.is_empty() {
            return result;
        }

        let Some(load_index) = history
            .iter()
            .rposition(|insn| self.is_register_jump_table_load(insn, jump_register))
        else {
            return result;
        };

        let load = &history[load_index];
        let Some((mem, operand_size)) = self.get_memory_source(load) else {
            return result;
        };
        let Some(case_count) = self.find_jump_table_case_count(mem.index(), history) else {
            return result;
        };

        if load.id == InsnId(X86Insn::X86_INS_MOV as u32) {
            let Some(table_base) = self.resolve_jump_table_base_from_history(mem, history) else {
                return result;
            };
            let entry_size = self.get_jump_table_entry_size(mem.scale() as usize, operand_size);
            if entry_size == 0 {
                return result;
            }
            for i in 0..case_count {
                let Some(entry_address) = table_base.checked_add((i * entry_size) as u64) else {
                    break;
                };
                let Some(target) = self.read_pointer_sized(entry_address, entry_size) else {
                    break;
                };
                if !self.is_executable_address(target) {
                    break;
                }
                result.insert(target);
            }
            return result;
        }

        if load.id != InsnId(X86Insn::X86_INS_MOVSXD as u32) {
            return result;
        }

        let Some(add_index) = history.iter().rposition(|insn| {
            self.is_add_same_register(insn, jump_register) && insn.address > load.address
        }) else {
            return result;
        };

        let Some(base_register) = self.get_add_rhs_register(&history[add_index], jump_register)
        else {
            return result;
        };
        let Some(table_base) = self.resolve_register_value_from_history(base_register, history)
        else {
            return result;
        };

        for i in 0..case_count {
            let Some(entry_address) = table_base.checked_add((i * 4) as u64) else {
                break;
            };
            let Some(offset) = self.read_i32(entry_address) else {
                break;
            };
            let target = (table_base as i64 + offset as i64) as u64;
            if !self.is_executable_address(target) {
                break;
            }
            result.insert(target);
        }

        result
    }

    fn is_register_jump_table_load(
        &self,
        instruction: &DecodedInstruction,
        register: RegId,
    ) -> bool {
        if instruction.operands.len() < 2 {
            return false;
        }
        if instruction.id != InsnId(X86Insn::X86_INS_MOV as u32)
            && instruction.id != InsnId(X86Insn::X86_INS_MOVSXD as u32)
        {
            return false;
        }

        matches!(
            (&instruction.operands[0], &instruction.operands[1]),
            (
                ArchOperand::X86Operand(dst),
                ArchOperand::X86Operand(src)
            ) if matches!(dst.op_type, X86OperandType::Reg(reg) if self.registers_match(reg, register))
                && matches!(src.op_type, X86OperandType::Mem(mem) if mem.index() != RegId(0))
        )
    }

    fn get_memory_source(&self, instruction: &DecodedInstruction) -> Option<(X86OpMem, usize)> {
        if instruction.operands.len() < 2 {
            return None;
        }
        match (&instruction.operands[0], &instruction.operands[1]) {
            (ArchOperand::X86Operand(_), ArchOperand::X86Operand(src)) => match src.op_type {
                X86OperandType::Mem(mem) => Some((mem, src.size as usize)),
                _ => None,
            },
            _ => None,
        }
    }

    fn is_add_same_register(&self, instruction: &DecodedInstruction, register: RegId) -> bool {
        if instruction.id != InsnId(X86Insn::X86_INS_ADD as u32) || instruction.operands.len() < 2 {
            return false;
        }
        matches!(
            &instruction.operands[0],
            ArchOperand::X86Operand(dst)
                if matches!(dst.op_type, X86OperandType::Reg(reg) if self.registers_match(reg, register))
        )
    }

    fn get_add_rhs_register(&self, instruction: &DecodedInstruction, lhs: RegId) -> Option<RegId> {
        if !self.is_add_same_register(instruction, lhs) {
            return None;
        }
        match &instruction.operands[1] {
            ArchOperand::X86Operand(op) => match op.op_type {
                X86OperandType::Reg(reg) => Some(reg),
                _ => None,
            },
            _ => None,
        }
    }

    fn find_jump_table_case_count(
        &self,
        index_register: RegId,
        history: &[DecodedInstruction],
    ) -> Option<usize> {
        for instruction in history.iter().rev() {
            if instruction.id != InsnId(X86Insn::X86_INS_CMP as u32)
                || instruction.operands.len() < 2
            {
                continue;
            }
            let lhs_matches = matches!(
                &instruction.operands[0],
                ArchOperand::X86Operand(op)
                    if matches!(op.op_type, X86OperandType::Reg(reg) if self.registers_match(reg, index_register))
            );
            if !lhs_matches {
                continue;
            }
            if let ArchOperand::X86Operand(rhs) = &instruction.operands[1] {
                if let X86OperandType::Imm(imm) = rhs.op_type {
                    let count = (imm + 1).max(0) as usize;
                    if (1..=256).contains(&count) {
                        return Some(count);
                    }
                }
            }
        }
        None
    }

    fn resolve_jump_table_base(
        &self,
        instruction: &Insn,
        mem: X86OpMem,
        history: &[DecodedInstruction],
    ) -> Option<u64> {
        if mem.base() == RegId(0) {
            return Some(mem.disp() as u64);
        }
        if mem.base() == RegId(X86_REG_RIP as u16) {
            return Some(
                (instruction.address() as i64 + mem.disp() + instruction.bytes().len() as i64)
                    as u64,
            );
        }
        self.resolve_register_value_from_history(mem.base(), history)
    }

    fn resolve_jump_table_base_from_history(
        &self,
        mem: X86OpMem,
        history: &[DecodedInstruction],
    ) -> Option<u64> {
        if mem.base() == RegId(0) {
            return Some(mem.disp() as u64);
        }
        self.resolve_register_value_from_history(mem.base(), history)
            .and_then(|base| base.checked_add(mem.disp() as u64))
    }

    fn resolve_register_value_from_history(
        &self,
        register: RegId,
        history: &[DecodedInstruction],
    ) -> Option<u64> {
        for instruction in history.iter().rev() {
            if instruction.id != InsnId(X86Insn::X86_INS_LEA as u32)
                || instruction.operands.len() < 2
            {
                continue;
            }
            let dst_matches = matches!(
                &instruction.operands[0],
                ArchOperand::X86Operand(dst)
                    if matches!(dst.op_type, X86OperandType::Reg(reg) if self.registers_match(reg, register))
            );
            if !dst_matches {
                continue;
            }
            if let ArchOperand::X86Operand(src) = &instruction.operands[1] {
                if let X86OperandType::Mem(mem) = src.op_type {
                    if mem.base() == RegId(X86_REG_RIP as u16) {
                        return Some(
                            (instruction.address as i64
                                + mem.disp()
                                + instruction.bytes.len() as i64)
                                as u64,
                        );
                    }
                    if mem.base() == RegId(0) {
                        return Some(mem.disp() as u64);
                    }
                }
            }
        }
        None
    }

    fn get_jump_table_entry_size(&self, scale: usize, operand_size: usize) -> usize {
        let pointer_size = match self.machine {
            Architecture::AMD64 => 8,
            Architecture::I386 => 4,
            _ => return 0,
        };

        if operand_size == pointer_size || operand_size == 4 {
            return operand_size;
        }
        if scale == pointer_size || scale == 4 {
            return scale;
        }
        0
    }

    fn registers_match(&self, lhs: RegId, rhs: RegId) -> bool {
        self.normalize_register(lhs) == self.normalize_register(rhs)
    }

    fn normalize_register(&self, register: RegId) -> u16 {
        let value = register.0 as u32;
        if [
            capstone::arch::x86::X86Reg::X86_REG_AL as u32,
            capstone::arch::x86::X86Reg::X86_REG_AH as u32,
            capstone::arch::x86::X86Reg::X86_REG_AX as u32,
            capstone::arch::x86::X86Reg::X86_REG_EAX as u32,
            capstone::arch::x86::X86Reg::X86_REG_RAX as u32,
        ]
        .contains(&value)
        {
            return capstone::arch::x86::X86Reg::X86_REG_RAX as u16;
        }
        if [
            capstone::arch::x86::X86Reg::X86_REG_CL as u32,
            capstone::arch::x86::X86Reg::X86_REG_CH as u32,
            capstone::arch::x86::X86Reg::X86_REG_CX as u32,
            capstone::arch::x86::X86Reg::X86_REG_ECX as u32,
            capstone::arch::x86::X86Reg::X86_REG_RCX as u32,
        ]
        .contains(&value)
        {
            return capstone::arch::x86::X86Reg::X86_REG_RCX as u16;
        }
        if [
            capstone::arch::x86::X86Reg::X86_REG_DL as u32,
            capstone::arch::x86::X86Reg::X86_REG_DH as u32,
            capstone::arch::x86::X86Reg::X86_REG_DX as u32,
            capstone::arch::x86::X86Reg::X86_REG_EDX as u32,
            capstone::arch::x86::X86Reg::X86_REG_RDX as u32,
        ]
        .contains(&value)
        {
            return capstone::arch::x86::X86Reg::X86_REG_RDX as u16;
        }
        if [
            capstone::arch::x86::X86Reg::X86_REG_BL as u32,
            capstone::arch::x86::X86Reg::X86_REG_BH as u32,
            capstone::arch::x86::X86Reg::X86_REG_BX as u32,
            capstone::arch::x86::X86Reg::X86_REG_EBX as u32,
            capstone::arch::x86::X86Reg::X86_REG_RBX as u32,
        ]
        .contains(&value)
        {
            return capstone::arch::x86::X86Reg::X86_REG_RBX as u16;
        }
        if [
            capstone::arch::x86::X86Reg::X86_REG_SI as u32,
            capstone::arch::x86::X86Reg::X86_REG_ESI as u32,
            capstone::arch::x86::X86Reg::X86_REG_RSI as u32,
        ]
        .contains(&value)
        {
            return capstone::arch::x86::X86Reg::X86_REG_RSI as u16;
        }
        if [
            capstone::arch::x86::X86Reg::X86_REG_DI as u32,
            capstone::arch::x86::X86Reg::X86_REG_EDI as u32,
            capstone::arch::x86::X86Reg::X86_REG_RDI as u32,
        ]
        .contains(&value)
        {
            return capstone::arch::x86::X86Reg::X86_REG_RDI as u16;
        }
        if [
            capstone::arch::x86::X86Reg::X86_REG_BP as u32,
            capstone::arch::x86::X86Reg::X86_REG_EBP as u32,
            capstone::arch::x86::X86Reg::X86_REG_RBP as u32,
        ]
        .contains(&value)
        {
            return capstone::arch::x86::X86Reg::X86_REG_RBP as u16;
        }
        if [
            capstone::arch::x86::X86Reg::X86_REG_SP as u32,
            capstone::arch::x86::X86Reg::X86_REG_ESP as u32,
            capstone::arch::x86::X86Reg::X86_REG_RSP as u32,
        ]
        .contains(&value)
        {
            return capstone::arch::x86::X86Reg::X86_REG_RSP as u16;
        }
        register.0
    }

    fn resolve_memory_operand_target(&self, instruction: &Insn, mem: X86OpMem) -> Option<u64> {
        let pointer_address = self.resolve_memory_operand_address(instruction, mem)?;
        let target = self.read_pointer(pointer_address)?;
        if !self.is_executable_address(target) {
            return None;
        }
        Some(target)
    }

    fn resolve_memory_operand_address(&self, instruction: &Insn, mem: X86OpMem) -> Option<u64> {
        if mem.index() != RegId(0) {
            return None;
        }

        if mem.base() == RegId(X86_REG_RIP as u16) {
            return Some(
                (instruction.address() as i64 + mem.disp() + instruction.bytes().len() as i64)
                    as u64,
            );
        }

        if self.machine == Architecture::I386 && mem.base() == RegId(0) {
            return Some(mem.disp() as u64);
        }

        None
    }

    fn read_pointer(&self, address: u64) -> Option<u64> {
        let pointer_size = match self.machine {
            Architecture::AMD64 => 8,
            Architecture::I386 => 4,
            _ => return None,
        };

        let start = address as usize;
        let end = start.checked_add(pointer_size)?;
        if end > self.image.len() {
            return None;
        }

        let bytes = &self.image[start..end];
        Some(match self.machine {
            Architecture::AMD64 => u64::from_le_bytes(bytes.try_into().ok()?),
            Architecture::I386 => u32::from_le_bytes(bytes.try_into().ok()?) as u64,
            _ => return None,
        })
    }

    fn read_pointer_sized(&self, address: u64, size: usize) -> Option<u64> {
        let start = address as usize;
        let end = start.checked_add(size)?;
        if end > self.image.len() {
            return None;
        }
        let bytes = &self.image[start..end];
        match size {
            4 => Some(u32::from_le_bytes(bytes.try_into().ok()?) as u64),
            8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
            _ => None,
        }
    }

    fn read_i32(&self, address: u64) -> Option<i32> {
        let start = address as usize;
        let end = start.checked_add(4)?;
        if end > self.image.len() {
            return None;
        }
        let bytes = &self.image[start..end];
        Some(i32::from_le_bytes(bytes.try_into().ok()?))
    }

    #[allow(dead_code)]
    pub fn get_call_immutable(&self, instruction: &Insn) -> Option<u64> {
        if Disassembler::is_call_instruction(instruction) {
            let operand = match self.get_instruction_operand(instruction, 0) {
                Ok(operand) => operand,
                Err(_error) => return None,
            };
            return Disassembler::get_operand_immutable(&operand);
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_operand_immutable(op: &ArchOperand) -> Option<u64> {
        if let ArchOperand::X86Operand(op) = op {
            if let X86OperandType::Imm(imm) = op.op_type {
                return Some(imm as u64);
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn get_instruction_operands(&self, instruction: &Insn) -> Result<Vec<ArchOperand>, Error> {
        #[allow(clippy::let_and_return)]
        let detail = match self.cs.insn_detail(instruction) {
            Ok(detail) => detail,
            Err(_error) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "failed to get instruction detail",
                ));
            }
        };
        let arch = detail.arch_detail();
        Ok(arch.operands())
    }

    #[allow(dead_code)]
    pub fn get_instruction_operand(
        &self,
        instruction: &Insn,
        index: usize,
    ) -> Result<ArchOperand, Error> {
        let operands = self.get_instruction_operands(instruction)?;
        let operand = match operands.get(index) {
            Some(operand) => operand.clone(),
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "failed to get instruction operand",
                ));
            }
        };
        Ok(operand)
    }

    #[allow(dead_code)]
    pub fn print_instructions(instructions: &Instructions) {
        for instruction in instructions.iter() {
            Disassembler::print_instruction(instruction);
        }
    }

    #[allow(dead_code)]
    pub fn get_instruction_edges(&self, instruction: &Insn) -> usize {
        if Disassembler::is_unconditional_jump_instruction(instruction) {
            return 1;
        }
        if Disassembler::is_return_instruction(instruction) {
            return 0;
        }
        if Disassembler::is_conditional_jump_instruction(instruction) {
            return 2;
        }
        0
    }

    #[allow(dead_code)]
    pub fn is_immutable_instruction_to_pattern(&self, instruction: &Insn) -> bool {
        let operands = match self.get_instruction_operands(instruction) {
            Ok(operands) => operands,
            Err(_) => return false,
        };
        Disassembler::is_immutable_instruction_to_pattern_with_operands(
            instruction,
            &operands,
            self.instruction_contains_immutable_operand(instruction),
        )
    }

    #[allow(dead_code)]
    pub fn is_unsupported_pattern_instruction(instruction: &Insn) -> bool {
        static MNEMONICS: &[u32] = &[
            X86Insn::X86_INS_MOVUPS as u32,
            X86Insn::X86_INS_MOVAPS as u32,
            X86Insn::X86_INS_XORPS as u32,
            X86Insn::X86_INS_SHUFPS as u32,
        ];
        MNEMONICS.contains(&instruction.id().0)
    }

    #[allow(dead_code)]
    pub fn is_return_instruction(insn: &Insn) -> bool {
        static RETURN_OPCODES: &[u32] = &[
            X86Insn::X86_INS_RET as u32,
            X86Insn::X86_INS_RETF as u32,
            X86Insn::X86_INS_RETFQ as u32,
            X86Insn::X86_INS_IRET as u32,
            X86Insn::X86_INS_IRETD as u32,
            X86Insn::X86_INS_IRETQ as u32,
        ];
        RETURN_OPCODES.contains(&insn.id().0)
    }

    #[allow(dead_code)]
    pub fn is_privilege_instruction(instruction: &Insn) -> bool {
        static MNEMONICS: &[u32] = &[
            X86Insn::X86_INS_HLT as u32,
            X86Insn::X86_INS_IN as u32,
            X86Insn::X86_INS_INSB as u32,
            X86Insn::X86_INS_INSW as u32,
            X86Insn::X86_INS_INSD as u32,
            X86Insn::X86_INS_OUT as u32,
            X86Insn::X86_INS_OUTSB as u32,
            X86Insn::X86_INS_OUTSW as u32,
            X86Insn::X86_INS_OUTSD as u32,
            X86Insn::X86_INS_RDMSR as u32,
            X86Insn::X86_INS_WRMSR as u32,
            X86Insn::X86_INS_RDPMC as u32,
            X86Insn::X86_INS_RDTSC as u32,
            X86Insn::X86_INS_LGDT as u32,
            X86Insn::X86_INS_LLDT as u32,
            X86Insn::X86_INS_LTR as u32,
            X86Insn::X86_INS_LMSW as u32,
            X86Insn::X86_INS_CLTS as u32,
            X86Insn::X86_INS_INVD as u32,
            X86Insn::X86_INS_INVLPG as u32,
            X86Insn::X86_INS_WBINVD as u32,
        ];
        MNEMONICS.contains(&instruction.id().0)
    }

    #[allow(dead_code)]
    pub fn is_wildcard_instruction(instruction: &Insn) -> bool {
        Disassembler::is_nop_instruction(instruction)
            || Disassembler::is_trap_instruction(instruction)
    }

    #[allow(dead_code)]
    pub fn is_nop_instruction(instruction: &Insn) -> bool {
        static MNEMONICS: &[u32] = &[X86Insn::X86_INS_NOP as u32, X86Insn::X86_INS_FNOP as u32];
        MNEMONICS.contains(&instruction.id().0)
    }

    #[allow(dead_code)]
    pub fn is_trap_instruction(instruction: &Insn) -> bool {
        static MNEMONICS: &[u32] = &[
            X86Insn::X86_INS_INT3 as u32,
            X86Insn::X86_INS_UD2 as u32,
            X86Insn::X86_INS_INT1 as u32,
            X86Insn::X86_INS_INTO as u32,
        ];
        MNEMONICS.contains(&instruction.id().0)
    }

    #[allow(dead_code)]
    pub fn is_jump_instruction(instruction: &Insn) -> bool {
        if Disassembler::is_conditional_jump_instruction(instruction) {
            return true;
        }
        if Disassembler::is_unconditional_jump_instruction(instruction) {
            return true;
        }
        false
    }

    #[allow(dead_code)]
    pub fn is_load_address_instruction(instruction: &Insn) -> bool {
        static MNEMONICS: &[u32] = &[X86Insn::X86_INS_LEA as u32];
        MNEMONICS.contains(&instruction.id().0)
    }

    #[allow(dead_code)]
    pub fn is_call_instruction(instruction: &Insn) -> bool {
        static MNEMONICS: &[u32] = &[X86Insn::X86_INS_CALL as u32, X86Insn::X86_INS_LCALL as u32];
        MNEMONICS.contains(&instruction.id().0)
    }

    #[allow(dead_code)]
    pub fn is_unconditional_jump_instruction(instruction: &Insn) -> bool {
        static MNEMONICS: &[u32] = &[X86Insn::X86_INS_JMP as u32];
        MNEMONICS.contains(&instruction.id().0)
    }

    #[allow(dead_code)]
    pub fn is_conditional_jump_instruction(instruction: &Insn) -> bool {
        static MNEMONICS: &[u32] = &[
            X86Insn::X86_INS_JNE as u32,
            X86Insn::X86_INS_JNO as u32,
            X86Insn::X86_INS_JNP as u32,
            X86Insn::X86_INS_JL as u32,
            X86Insn::X86_INS_JLE as u32,
            X86Insn::X86_INS_JG as u32,
            X86Insn::X86_INS_JGE as u32,
            X86Insn::X86_INS_JE as u32,
            X86Insn::X86_INS_JECXZ as u32,
            X86Insn::X86_INS_JCXZ as u32,
            X86Insn::X86_INS_JB as u32,
            X86Insn::X86_INS_JBE as u32,
            X86Insn::X86_INS_JA as u32,
            X86Insn::X86_INS_JAE as u32,
            X86Insn::X86_INS_JNS as u32,
            X86Insn::X86_INS_JO as u32,
            X86Insn::X86_INS_JP as u32,
            X86Insn::X86_INS_JRCXZ as u32,
            X86Insn::X86_INS_JS as u32,
            X86Insn::X86_INS_LOOPE as u32,
            X86Insn::X86_INS_LOOPNE as u32,
            X86Insn::X86_INS_LOOP as u32,
        ];
        MNEMONICS.contains(&instruction.id().0)
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

    pub fn disassemble_instructions(
        &self,
        address: u64,
        count: u64,
    ) -> Result<Instructions<'_>, Error> {
        if (address as usize) >= self.image.len() {
            return Err(Error::new(ErrorKind::Other, "address out of bounds"));
        }
        let instructions = self
            .cs
            .disasm_count(&self.image[address as usize..], address, count as usize)
            .map_err(|_| Error::new(ErrorKind::Other, "failed to disassemble instructions"))?;
        if instructions.len() == 0 {
            return Err(Error::new(ErrorKind::Other, "no instructions found"));
        }
        Ok(instructions)
    }

    fn cs_new(machine: Architecture, detail: bool) -> Result<Capstone, Error> {
        match machine {
            Architecture::AMD64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(detail)
                .build()
                .map_err(|e| Error::new(ErrorKind::Other, format!("capstone error: {:?}", e))),
            Architecture::I386 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(detail)
                .build()
                .map_err(|e| Error::new(ErrorKind::Other, format!("capstone error: {:?}", e))),
            _ => Err(Error::new(ErrorKind::Other, "unsupported architecture")),
        }
    }
}
