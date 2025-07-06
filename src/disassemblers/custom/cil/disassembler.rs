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
            .map_err(|error| Error::new(ErrorKind::Other, format!("{}", error)))?;

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
