//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

extern crate capstone;
use crate::binary::Binary;
use crate::controlflow::graph::Graph;
use crate::controlflow::instruction::Instruction;
use crate::io::Stderr;
use crate::Architecture;
use crate::Config;
use arch::x86::X86OpMem;
use arch::x86::X86Reg::{X86_REG_EBP, X86_REG_ESP, X86_REG_RBP, X86_REG_RIP, X86_REG_RSP};
use capstone::arch::x86::X86Insn;
use capstone::arch::x86::X86OperandType;
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use capstone::Insn;
use capstone::InsnId;
use capstone::Instructions;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Error;
use std::io::ErrorKind;

pub struct Disassembler<'disassembler> {
    cs: Capstone,
    image: &'disassembler [u8],
    machine: Architecture,
    executable_address_ranges: BTreeMap<u64, u64>,
    config: Config,
}

impl<'disassembler> Disassembler<'disassembler> {
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

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.executable_address_ranges
            .iter()
            .any(|(start, end)| address >= *start && address <= *end)
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
    pub fn disassemble_controlflow<'a>(
        &'a self,
        addresses: BTreeSet<u64>,
        cfg: &'a mut Graph,
    ) -> Result<(), Error> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(cfg.config.general.threads)
            .build()
            .map_err(|error| Error::new(ErrorKind::Other, format!("{}", error)))?;

        if cfg.config.disassembler.sweep.enabled {
            cfg.functions.enqueue_extend(self.disassemble_sweep());
        }

        cfg.functions.enqueue_extend(addresses);

        let external_image = self.image;

        let external_machine = self.machine.clone();

        let external_executable_address_ranges = self.executable_address_ranges.clone();

        let external_config = self.config.clone();

        pool.install(|| {
            while !cfg.functions.queue.is_empty() {
                let function_addresses = cfg.functions.dequeue_all();
                cfg.functions
                    .insert_processed_extend(function_addresses.clone());
                let graphs: Vec<Graph> = function_addresses
                    .par_iter()
                    .map(|address| {
                        let machine = external_machine.clone();
                        let executable_address_ranges = external_executable_address_ranges.clone();
                        let image = external_image;
                        let mut graph = Graph::new(machine, cfg.config.clone());
                        if let Ok(disasm) = Disassembler::new(
                            machine,
                            image,
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
            Stderr::print_debug(cfg.config.clone(), &error_message);
            return Err(Error::new(ErrorKind::Other, error_message));
        }

        cfg.blocks.enqueue(address);

        while let Some(block_start_address) = cfg.blocks.dequeue() {
            if cfg.blocks.is_processed(block_start_address) {
                continue;
            }

            let block_end_address =
                self.disassemble_block(block_start_address, cfg)
                    .map_err(|error| {
                        cfg.functions.insert_invalid(address);
                        error
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
            Stderr::print_debug(cfg.config.clone(), error.clone());
            return Err(Error::new(ErrorKind::Other, error));
        }

        let instruction_container = self.disassemble_instructions(address, 1)?;
        let instruction = instruction_container.iter().next().ok_or_else(|| {
            cfg.instructions.insert_invalid(address);
            let error = format!("0x{:x}: failed to disassemble instruction", address);
            Error::new(ErrorKind::Other, error)
        })?;

        let instruction_signature = self.get_instruction_pattern(&instruction)?;

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
        blinstruction.pattern = instruction_signature;

        if let Some(addr) = self.get_conditional_jump_immutable(instruction) {
            blinstruction.to.insert(addr);
        }
        if let Some(addr) = self.get_unconditional_jump_immutable(instruction) {
            blinstruction.to.insert(addr);
        }
        if let Some(addr) = self.get_call_immutable(instruction) {
            cfg.functions.enqueue(addr);
            blinstruction.functions.insert(addr);
        }
        if let Some(addr) = self.get_instruction_executable_addresses(instruction) {
            cfg.functions.enqueue(addr);
            blinstruction.functions.insert(addr);
        }

        Stderr::print_debug(
            cfg.config.clone(),
            format!(
                "0x{:x}: mnemonic: {:?}, next: {:?}, to: {:?}",
                blinstruction.address,
                instruction.mnemonic().unwrap(),
                blinstruction.next(),
                blinstruction.to()
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
            Stderr::print_debug(cfg.config.clone(), error_message.clone());
            return Err(Error::new(ErrorKind::Other, error_message));
        }

        let mut pc = address;
        let mut has_prologue = false;

        while let Ok(_) = self.disassemble_instruction(pc, cfg) {
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

            if instruction.is_trap || instruction.is_return || instruction.is_jump || is_block_start
            {
                break;
            }

            pc += instruction.size() as u64;
        }

        if has_prologue {
            cfg.functions.enqueue(address);
        }
        cfg.blocks.insert_valid(address);

        Ok(pc)
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
                        && instructions[1].id() != InsnId(X86Insn::X86_INS_MOV as u32)
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
                        && instructions[1].id() != InsnId(X86Insn::X86_INS_MOV as u32)
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
                    ))
                }
            }
        }
        Ok(result)
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
        return false;
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
        return false;
    }

    #[allow(dead_code)]
    pub fn get_instruction_pattern(&self, instruction: &Insn) -> Result<String, Error> {
        if Disassembler::is_unsupported_pattern_instruction(instruction) {
            return Ok(Binary::to_hex(instruction.bytes()));
        }

        if Disassembler::is_wildcard_instruction(instruction) {
            return Ok("??".repeat(instruction.bytes().len()));
        }

        if !self.instruction_contains_immutable_operand(instruction)
            && !self.instruction_contains_memory_operand(instruction)
        {
            return Ok(Binary::to_hex(instruction.bytes()));
        }

        let instruction_size = instruction.bytes().len() * 8;

        let mut wildcarded = vec![false; instruction_size];

        let instruction_trailing_null_size = instruction
            .bytes()
            .iter()
            .rev()
            .take_while(|&&b| b == 0)
            .count()
            * 8;

        let operands = self.get_instruction_operands(instruction)?;

        let total_operand_size = self.get_instruction_total_operand_size(instruction)?;

        if total_operand_size > instruction_size {
            return Ok(Binary::to_hex(instruction.bytes()));
        }

        let instruction_trailing_null_offset = instruction_size - instruction_trailing_null_size;

        let is_immutable_signature = self.is_immutable_instruction_to_pattern(instruction);

        if total_operand_size <= 0 && operands.len() > 0 {
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

                let displacement_size = match op.op_type {
                    X86OperandType::Mem(op_mem) => {
                        Disassembler::get_displacement_size(op_mem.disp() as u64) * 8
                    }
                    _ => 0,
                };

                let mut op_size = if (op.size as usize) > displacement_size {
                    op.size as usize
                } else {
                    displacement_size
                };

                if op_size > instruction_size {
                    op_size = op.size as usize;
                }

                if op_size > instruction_size {
                    Disassembler::print_instruction(instruction);
                    return Err(Error::new(ErrorKind::Other, format!("Instruction -> 0x{:x}: instruction operand size exceeds instruction size", instruction.address())));
                }

                let operand_offset = instruction_size - op_size;

                if should_wildcard {
                    for i in 0..op_size as usize {
                        if operand_offset + i > wildcarded.len() {
                            Disassembler::print_instruction(instruction);
                            return Err(Error::new(ErrorKind::Other, format!("Instruction -> 0x{:x}: instruction wildcard index is out of bounds", instruction.address())));
                        }
                        wildcarded[operand_offset + i] = true;
                    }
                }
            }
        }

        let instruction_hex = Binary::to_hex(instruction.bytes());

        if instruction_hex.len() % 2 != 0 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Instruction -> 0x{:x}: instruction hex string length is not even",
                    instruction.address()
                ),
            ));
        }

        let signature: String = instruction_hex
            .chars()
            .enumerate()
            .map(|(index, ch)| {
                let start = index * 4;
                let end = start + 4;
                if start >= instruction_trailing_null_offset && is_immutable_signature {
                    '?'
                } else if wildcarded[start..end].iter().all(|&x| x) {
                    '?'
                } else {
                    ch
                }
            })
            .collect();

        if signature.len() % 2 != 0 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Instruction -> 0x{:x}: wildcarded hex string length is not even",
                    instruction.address()
                ),
            ));
        }

        if instruction_hex.len() != signature.len() {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Instruction -> 0x{:x}: instruction hex length not same as wildcard hex length",
                    instruction.address()
                ),
            ));
        }

        return Ok(signature);
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
                    if mem.base() != RegId(X86_REG_RIP as u16) {
                        continue;
                    }
                    if mem.index() != RegId(0) {
                        continue;
                    }
                    let address: u64 = (instruction.address() as i64
                        + mem.disp()
                        + instruction.bytes().len() as i64)
                        as u64;
                    if !self.is_executable_address(address) {
                        continue;
                    }
                    if self.disassemble_instructions(address, 1).is_err() {
                        continue;
                    }
                    return Some(address);
                }
            }
        }
        None
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
        let detail = match self.cs.insn_detail(&instruction) {
            Ok(detail) => detail,
            Err(_error) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "failed to get instruction detail",
                ))
            }
        };
        let arch = detail.arch_detail();
        return Ok(arch.operands());
    }

    #[allow(dead_code)]
    pub fn get_instruction_operand(
        &self,
        instruction: &Insn,
        index: usize,
    ) -> Result<ArchOperand, Error> {
        let operands = match self.get_instruction_operands(instruction) {
            Ok(operands) => operands,
            Err(error) => return Err(error),
        };
        let operand = match operands.get(index) {
            Some(operand) => operand.clone(),
            None => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "failed to get instruction operand",
                ))
            }
        };
        return Ok(operand);
    }

    #[allow(dead_code)]
    pub fn print_instructions(instructions: &Instructions) {
        for instruction in instructions.iter() {
            Disassembler::print_instruction(&instruction);
        }
    }

    #[allow(dead_code)]
    pub fn get_instruction_edges(&self, instruction: &Insn) -> usize {
        if Disassembler::is_unconditional_jump_instruction(instruction) {
            return 1;
        }
        if Disassembler::is_return_instruction(instruction) {
            return 1;
        }
        if Disassembler::is_conditional_jump_instruction(instruction) {
            return 2;
        }
        0
    }

    #[allow(dead_code)]
    pub fn is_immutable_instruction_to_pattern(&self, instruction: &Insn) -> bool {
        if !self.instruction_contains_immutable_operand(instruction) {
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
            let operands = match self.get_instruction_operands(instruction) {
                Ok(operands) => operands,
                Err(_) => return false,
            };

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
    pub fn is_unsupported_pattern_instruction(instruction: &Insn) -> bool {
        vec![
            InsnId(X86Insn::X86_INS_MOVUPS as u32),
            InsnId(X86Insn::X86_INS_MOVAPS as u32),
            InsnId(X86Insn::X86_INS_XORPS as u32),
            InsnId(X86Insn::X86_INS_SHUFPS as u32),
        ]
        .contains(&instruction.id())
    }

    #[allow(dead_code)]
    pub fn is_return_instruction(instruction: &Insn) -> bool {
        vec![
            InsnId(X86Insn::X86_INS_RET as u32),
            InsnId(X86Insn::X86_INS_RETF as u32),
            InsnId(X86Insn::X86_INS_RETFQ as u32),
            InsnId(X86Insn::X86_INS_IRET as u32),
            InsnId(X86Insn::X86_INS_IRETD as u32),
            InsnId(X86Insn::X86_INS_IRETQ as u32),
        ]
        .contains(&instruction.id())
    }

    #[allow(dead_code)]
    pub fn is_privilege_instruction(instruction: &Insn) -> bool {
        vec![
            InsnId(X86Insn::X86_INS_HLT as u32),
            InsnId(X86Insn::X86_INS_IN as u32),
            InsnId(X86Insn::X86_INS_INSB as u32),
            InsnId(X86Insn::X86_INS_INSW as u32),
            InsnId(X86Insn::X86_INS_INSD as u32),
            InsnId(X86Insn::X86_INS_OUT as u32),
            InsnId(X86Insn::X86_INS_OUTSB as u32),
            InsnId(X86Insn::X86_INS_OUTSW as u32),
            InsnId(X86Insn::X86_INS_OUTSD as u32),
            InsnId(X86Insn::X86_INS_RDMSR as u32),
            InsnId(X86Insn::X86_INS_WRMSR as u32),
            InsnId(X86Insn::X86_INS_RDPMC as u32),
            InsnId(X86Insn::X86_INS_RDTSC as u32),
            InsnId(X86Insn::X86_INS_LGDT as u32),
            InsnId(X86Insn::X86_INS_LLDT as u32),
            InsnId(X86Insn::X86_INS_LTR as u32),
            InsnId(X86Insn::X86_INS_LMSW as u32),
            InsnId(X86Insn::X86_INS_CLTS as u32),
            InsnId(X86Insn::X86_INS_INVD as u32),
            InsnId(X86Insn::X86_INS_INVLPG as u32),
            InsnId(X86Insn::X86_INS_WBINVD as u32),
        ]
        .contains(&instruction.id())
    }

    #[allow(dead_code)]
    pub fn is_wildcard_instruction(instruction: &Insn) -> bool {
        Disassembler::is_nop_instruction(instruction)
            || Disassembler::is_trap_instruction(instruction)
    }

    #[allow(dead_code)]
    pub fn is_nop_instruction(instruction: &Insn) -> bool {
        vec![
            InsnId(X86Insn::X86_INS_NOP as u32),
            InsnId(X86Insn::X86_INS_FNOP as u32),
        ]
        .contains(&instruction.id())
    }

    #[allow(dead_code)]
    pub fn is_trap_instruction(instruction: &Insn) -> bool {
        vec![
            InsnId(X86Insn::X86_INS_INT3 as u32),
            InsnId(X86Insn::X86_INS_UD2 as u32),
            InsnId(X86Insn::X86_INS_INT1 as u32),
            InsnId(X86Insn::X86_INS_INTO as u32),
        ]
        .contains(&instruction.id())
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
        vec![InsnId(X86Insn::X86_INS_LEA as u32)].contains(&instruction.id())
    }

    #[allow(dead_code)]
    pub fn is_call_instruction(instruction: &Insn) -> bool {
        vec![
            InsnId(X86Insn::X86_INS_CALL as u32),
            InsnId(X86Insn::X86_INS_LCALL as u32),
        ]
        .contains(&instruction.id())
    }

    #[allow(dead_code)]
    pub fn is_unconditional_jump_instruction(instruction: &Insn) -> bool {
        vec![InsnId(X86Insn::X86_INS_JMP as u32)].contains(&instruction.id())
    }

    #[allow(dead_code)]
    pub fn is_conditional_jump_instruction(instruction: &Insn) -> bool {
        vec![
            InsnId(X86Insn::X86_INS_JNE as u32),
            InsnId(X86Insn::X86_INS_JNO as u32),
            InsnId(X86Insn::X86_INS_JNP as u32),
            InsnId(X86Insn::X86_INS_JL as u32),
            InsnId(X86Insn::X86_INS_JLE as u32),
            InsnId(X86Insn::X86_INS_JG as u32),
            InsnId(X86Insn::X86_INS_JGE as u32),
            InsnId(X86Insn::X86_INS_JE as u32),
            InsnId(X86Insn::X86_INS_JECXZ as u32),
            InsnId(X86Insn::X86_INS_JCXZ as u32),
            InsnId(X86Insn::X86_INS_JB as u32),
            InsnId(X86Insn::X86_INS_JBE as u32),
            InsnId(X86Insn::X86_INS_JA as u32),
            InsnId(X86Insn::X86_INS_JAE as u32),
            InsnId(X86Insn::X86_INS_JNS as u32),
            InsnId(X86Insn::X86_INS_JO as u32),
            InsnId(X86Insn::X86_INS_JP as u32),
            InsnId(X86Insn::X86_INS_JRCXZ as u32),
            InsnId(X86Insn::X86_INS_JS as u32),
            InsnId(X86Insn::X86_INS_LOOPE as u32),
            InsnId(X86Insn::X86_INS_LOOPNE as u32),
        ]
        .contains(&instruction.id())
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
        if instructions.len() <= 0 {
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
