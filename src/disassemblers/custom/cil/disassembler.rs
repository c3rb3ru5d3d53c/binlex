use std::io::Error;
use std::io::ErrorKind;
use crate::Architecture;
use std::collections::BTreeMap;
use crate::controlflow::Graph;
use crate::controlflow::Instruction as CFGInstruction;
use crate::disassemblers::custom::cil::Instruction;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;
use std::collections::BTreeSet;
use crate::io::Stderr;

pub struct Disassembler <'disassembler> {
    pub architecture: Architecture,
    pub executable_address_ranges: BTreeMap<u64, u64>,
    pub image: &'disassembler [u8]
}

impl <'disassembler> Disassembler <'disassembler> {
    pub fn new(architecture: Architecture, image: &'disassembler[u8], executable_address_rannges: BTreeMap<u64, u64>) -> Result<Self, Error> {
        match architecture {
            Architecture::CIL => {},
            _ => {
                return Err(Error::new(ErrorKind::Unsupported, "unsupported architecture"));
            }
        }
        Ok(Self {
            architecture: architecture,
            executable_address_ranges: executable_address_rannges,
            image: image
        })
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.executable_address_ranges
            .iter()
            .any(|(start, end)| address >= *start && address <= *end)
    }

    pub fn disassemble_instruction(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {

        cfg.instructions.insert_processed(address);

        if self.is_executable_address(address) == false {
            cfg.instructions.insert_invalid(address);
            return Err(Error::new(ErrorKind::InvalidData, format!("0x{:x}: instruction address is not executable", address)));
        }

        let instruction = match Instruction::new(&self.image[address as usize..], address) {
            Ok(instruction) => instruction,
            Err(_) => {
                cfg.instructions.insert_invalid(address);
                return Err(Error::new(ErrorKind::Unsupported, format!("0x{:x}: failed to disassemble instruction", address)));
            }
        };

        let mut cfginstruction = CFGInstruction::create(address, self.architecture, cfg.config.clone());

        cfginstruction.bytes = instruction.bytes();
        cfginstruction.is_call = instruction.is_call();
        cfginstruction.is_jump = instruction.is_jump();
        cfginstruction.is_conditional = instruction.is_conditional_jump();
        cfginstruction.is_return = instruction.is_return();
        cfginstruction.is_trap = false;
        cfginstruction.pattern = instruction.pattern();
        cfginstruction.edges = instruction.edges();
        cfginstruction.to = instruction.to();

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

        if self.is_executable_address(address) == false {
            return Err(Error::new(ErrorKind::InvalidData, format!("0x{:x}: block address is not executable", address)));
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
                    return Err(Error::new(ErrorKind::InvalidData, format!("0x{:x}: failed to disassemble instruction", pc)));
                }
            };

            if instruction.address == address {
                instruction.is_block_start = true;
                cfg.update_instruction(instruction.clone());
            }

            let is_block_start = instruction.address != address && instruction.is_block_start;

            if instruction.is_trap || instruction.is_return || instruction.is_jump || is_block_start {
                break;
            }

            pc += instruction.size() as u64;
        }

        cfg.blocks.insert_valid(address);

        Ok(pc)
    }

    pub fn disassemble_function(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        cfg.functions.insert_processed(address);

        if self.is_executable_address(address) == false {
            return Err(Error::new(ErrorKind::InvalidData, format!("0x{:x}: function address is not executable", address)));
        }

        cfg.blocks.enqueue(address);

        while let Some(block_start_address) = cfg.blocks.dequeue() {
            if cfg.blocks.is_processed(block_start_address) { continue; }

            let block_end_address = self
                .disassemble_block(block_start_address, cfg)
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

    pub fn disassemble_controlflow<'a>(&'a self, addresses: BTreeSet<u64>, cfg: &'a mut Graph) -> Result<(), Error> {

        let pool = ThreadPoolBuilder::new()
            .num_threads(cfg.config.general.threads)
            .build()
            .map_err(|error| Error::new(ErrorKind::Other, format!("{}", error)))?;

        cfg.functions.enqueue_extend(addresses);

        let external_image = self.image;

        let external_machine = self.architecture.clone();

        let external_executable_address_ranges = self.executable_address_ranges.clone();

        pool.install(|| {
            while !cfg.functions.queue.is_empty() {
                let function_addresses = cfg.functions.dequeue_all();
                cfg.functions.insert_processed_extend(function_addresses.clone());
                let graphs: Vec<Graph> = function_addresses
                    .par_iter()
                    .map(|address| {
                        let machine = external_machine.clone();
                        let executable_address_ranges = external_executable_address_ranges.clone();
                        let image = external_image;
                        let mut graph = Graph::new(machine, cfg.config.clone());
                        if let Ok(disasm) = Disassembler::new(machine, image, executable_address_ranges) {
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

        return Ok(());
    }
}
