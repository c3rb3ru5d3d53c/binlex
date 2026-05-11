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
use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::controlflow::InstructionRecord;
use crate::disassemblers::arm64::classify as arm64_classify;
use crate::disassemblers::arm64::decoded::Arm64DecodedInstruction;
use crate::disassemblers::arm64::metrics::{self as arm64_metrics, DisassemblyMetrics};
use crate::disassemblers::arm64::pattern::instruction_chromosome_mask;
use crate::disassemblers::arm64::{
    prologue as arm64_prologue, sweep as arm64_sweep, translate as arm64_translate,
};
use crate::io::Stderr;
use ::capstone::Insn;
use ::capstone::prelude::*;
use rayon::ThreadPoolBuilder;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Capstone,
}

pub struct Disassembler<'a> {
    pub(crate) cs: Capstone,
    machine: Architecture,
    pub(crate) image: &'a [u8],
    pub(crate) image_base: u64,
    executable_address_ranges: BTreeMap<u64, u64>,
    config: Configuration,
    selected_backend: Backend,
    pub(crate) metrics: Arc<DisassemblyMetrics>,
    decoded_instruction_cache: Mutex<HashMap<u64, Arm64DecodedInstruction>>,
    known_instruction_addresses: Arc<BTreeSet<u64>>,
    known_block_addresses: Arc<BTreeSet<u64>>,
    known_function_addresses: Arc<BTreeSet<u64>>,
}

impl<'a> Disassembler<'a> {
    fn group_function_addresses_for_backend(
        backend: Backend,
        addresses: &BTreeSet<u64>,
    ) -> Vec<Vec<u64>> {
        match backend {
            Backend::Capstone => arm64_metrics::group_function_addresses(addresses, 4),
        }
    }

    fn with_backend_state(
        backend: Backend,
        machine: Architecture,
        image: &'a [u8],
        image_base: u64,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
        metrics: Arc<DisassemblyMetrics>,
        known_instruction_addresses: Arc<BTreeSet<u64>>,
        known_block_addresses: Arc<BTreeSet<u64>>,
        known_function_addresses: Arc<BTreeSet<u64>>,
    ) -> Result<Self, Error> {
        let cs = match backend {
            Backend::Capstone => Self::cs_new(machine, true)?,
        };

        Ok(Self {
            cs,
            machine,
            image,
            image_base,
            executable_address_ranges,
            config,
            selected_backend: backend,
            metrics,
            decoded_instruction_cache: Mutex::new(HashMap::new()),
            known_instruction_addresses,
            known_block_addresses,
            known_function_addresses,
        })
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
        Self::with_backend(
            Backend::Capstone,
            machine,
            image,
            image_base,
            executable_address_ranges,
            config,
        )
    }

    pub fn with_backend(
        backend: Backend,
        machine: Architecture,
        image: &'a [u8],
        image_base: u64,
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Configuration,
    ) -> Result<Self, Error> {
        Self::with_backend_state(
            backend,
            machine,
            image,
            image_base,
            executable_address_ranges,
            config,
            Arc::new(DisassemblyMetrics::default()),
            Arc::new(BTreeSet::new()),
            Arc::new(BTreeSet::new()),
            Arc::new(BTreeSet::new()),
        )
    }

    pub(crate) fn image_offset(&self, address: u64) -> Option<usize> {
        address
            .checked_sub(self.image_base)
            .map(|offset| offset as usize)
            .filter(|offset| *offset <= self.image.len())
    }

    pub fn disassemble_instruction_address(
        &self,
        address: u64,
        cfg: &mut Graph,
    ) -> Result<u64, Error> {
        let instruction_started_at = match self.begin_instruction(address, cfg)? {
            Some(started_at) => started_at,
            None => {
                let instruction = cfg
                    .get_instruction(address)
                    .expect("instruction cached after begin_instruction");
                return Ok(instruction.address);
            }
        };

        let finish_invalid = |cfg: &mut Graph| {
            self.finish_instruction_invalid(address, cfg, instruction_started_at);
        };

        if let Some(instruction) = cfg.get_instruction(address) {
            return Ok(instruction.address);
        }

        let instruction = self
            .prepare_instruction(self.machine, address, cfg)
            .map_err(|_| {
                finish_invalid(cfg);
                let error = format!("0x{:x}: failed to disassemble instruction", address);
                Error::other(error)
            })?;

        Stderr::print_debug(
            &cfg.config,
            format!(
                "0x{:x}: mnemonic: {:?}, fallthrough: {:?}, branches: {:?}, is_conditional: {:?}, is_jump: {:?}",
                instruction.address,
                instruction.mnemonic,
                instruction.fallthrough(),
                instruction.branches(),
                instruction.is_conditional,
                instruction.is_jump,
            ),
        );

        cfg.functions.enqueue_extend(instruction.functions.clone());
        cfg.insert_instruction(instruction);
        self.finish_instruction_valid(address, cfg, instruction_started_at);

        Ok(address)
    }

    fn is_function_prologue(&self, address: u64) -> bool {
        let Ok(instructions) = self.disassemble_instructions(address, 2) else {
            return false;
        };
        if instructions.len() < 2 {
            return false;
        }
        if instructions[0].mnemonic().unwrap_or("") != "stp"
            || instructions[1].mnemonic().unwrap_or("") != "mov"
        {
            return false;
        }
        arm64_prologue::is_function_prologue(|instruction_index, operand_index| {
            self.decode_instruction_operand(&instructions[instruction_index], operand_index)
        })
    }

    pub fn disassemble_block_address(&self, address: u64, cfg: &mut Graph) -> Result<u64, Error> {
        let block_started_at = match self.begin_block(address, cfg)? {
            Some(started_at) => started_at,
            None => return Ok(address),
        };

        let mut pc = address;
        let mut has_prologue = false;
        let mut terminator = address;
        let mut split_successor: Option<u64> = None;

        while self.disassemble_instruction_address(pc, cfg).is_ok() {
            let mut instruction = match cfg.get_instruction_record(pc) {
                Some(instr) => instr,
                None => {
                    self.finish_block_invalid(address, cfg, block_started_at);
                    return Err(Error::other("failed to disassemble instruction"));
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

            if self.has_known_instruction_address(pc) {
                split_successor = Some(pc);
                self.record_shared_tail_split();
                break;
            }

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

        self.finish_block_valid(address, cfg, block_started_at);

        Ok(terminator)
    }

    pub fn disassemble_function_address(
        &self,
        address: u64,
        cfg: &mut Graph,
    ) -> Result<u64, Error> {
        let function_started_at = match self.begin_function(address, cfg)? {
            Some(started_at) => started_at,
            None => return Ok(address),
        };

        cfg.blocks.enqueue(address);

        while let Some(block_start_address) = cfg.blocks.dequeue() {
            if cfg.blocks.is_processed(block_start_address) {
                continue;
            }

            let block_end_address = self
                .disassemble_block_address(block_start_address, cfg)
                .inspect_err(|_| {
                    self.finish_function_invalid(address, cfg, function_started_at);
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

        self.finish_function_valid(address, cfg, function_started_at);

        Ok(address)
    }

    pub fn disassemble_instruction<'g>(
        &self,
        address: u64,
        cfg: &'g mut Graph,
    ) -> Result<Instruction<'g>, Error> {
        let entry = self.disassemble_instruction_address(address, cfg)?;
        cfg.get_instruction(entry)
            .ok_or_else(|| Error::other(format!("0x{entry:x}: instruction missing after disassembly")))
    }

    pub fn disassemble_block<'g>(
        &self,
        address: u64,
        cfg: &'g mut Graph,
    ) -> Result<Block<'g>, Error> {
        self.disassemble_block_address(address, cfg)?;
        cfg.get_block(address)
            .ok_or_else(|| Error::other(format!("0x{address:x}: block missing after disassembly")))
    }

    pub fn disassemble_function<'g>(
        &self,
        address: u64,
        cfg: &'g mut Graph,
    ) -> Result<Function<'g>, Error> {
        self.disassemble_function_address(address, cfg)?;
        cfg.get_function(address)
            .ok_or_else(|| Error::other(format!("0x{address:x}: function missing after disassembly")))
    }

    pub fn disassemble(&self, addresses: BTreeSet<u64>, cfg: &mut Graph) -> Result<(), Error> {
        let disassembly_started_at = Instant::now();
        let pool = ThreadPoolBuilder::new()
            .num_threads(cfg.config.resolved_threads())
            .build()
            .map_err(|error| Error::other(format!("{}", error)))?;

        let mut seed_addresses = addresses;
        seed_addresses.extend(self.disassemble_sweep());
        cfg.functions.enqueue_extend(seed_addresses);

        let external_image = self.image;
        let external_machine = self.machine;
        let external_executable_address_ranges = self.executable_address_ranges.clone();
        let external_config = self.config.clone();
        let external_metrics = self.metrics.clone();
        let selected_backend = self.selected_backend;
        let graph_config = cfg.config.clone();
        let batch_width = cfg.config.resolved_threads().max(1);
        let image_base = self.image_base;

        pool.install(|| {
            while !cfg.functions.queue.is_empty() {
                let pending_addresses: Vec<u64> = cfg.functions.dequeue_all().into_iter().collect();
                for chunk in pending_addresses.chunks(batch_width) {
                    let known_instruction_addresses = Arc::new(cfg.instruction_addresses());
                    let known_block_addresses = Arc::new(cfg.blocks.valid_addresses());
                    let known_function_addresses = Arc::new(cfg.functions.valid_addresses());
                    let function_addresses: BTreeSet<u64> = chunk
                        .iter()
                        .copied()
                        .filter(|address| {
                            !cfg.functions.is_valid(*address)
                                && !cfg.is_instruction_address(*address)
                        })
                        .collect();
                    if function_addresses.is_empty() {
                        continue;
                    }

                    cfg.functions
                        .insert_processed_extend(function_addresses.clone());
                    let function_groups = Self::group_function_addresses_for_backend(
                        selected_backend,
                        &function_addresses,
                    );
                    let graphs: Vec<Graph> = function_groups
                        .par_iter()
                        .map_init(
                            || {
                                Disassembler::with_backend_state(
                                    selected_backend,
                                    external_machine,
                                    external_image,
                                    image_base,
                                    external_executable_address_ranges.clone(),
                                    external_config.clone(),
                                    external_metrics.clone(),
                                    known_instruction_addresses.clone(),
                                    known_block_addresses.clone(),
                                    known_function_addresses.clone(),
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
                        let merge_started_at = Instant::now();
                        cfg.merge(&mut graph);
                        arm64_metrics::record_merge_elapsed_for_metrics(
                            &external_metrics,
                            merge_started_at,
                            graph_config.debug,
                        );
                    }
                }
            }
        });

        self.emit_disassembly_metrics(cfg, disassembly_started_at);

        Ok(())
    }

    pub fn disassemble_sweep(&self) -> BTreeSet<u64> {
        arm64_sweep::disassemble(
            self.machine,
            &self.executable_address_ranges,
            &self.config,
            &self.metrics,
            |address, graph| self.prepare_instruction(self.machine, address, graph),
            |address| self.is_executable_address(address),
        )
    }

    pub(crate) fn metric_inc(&self, counter: &AtomicU64, value: u64) {
        if cfg!(debug_assertions) {
            counter.fetch_add(value, Ordering::Relaxed);
        } else {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }

    pub(crate) fn metric_elapsed(&self, counter: &AtomicU64, started_at: Instant) {
        if cfg!(debug_assertions) {
            counter.fetch_add(started_at.elapsed().as_micros() as u64, Ordering::Relaxed);
        } else {
            counter.fetch_add(started_at.elapsed().as_micros() as u64, Ordering::Relaxed);
        }
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
    ) -> Result<InstructionRecord, Error> {
        arm64_translate::build_instruction(self, machine, address, cfg)
    }

    pub(crate) fn emit_disassembly_metrics(&self, cfg: &Graph, disassembly_started_at: Instant) {
        arm64_metrics::log_disassembly_metrics(&cfg.config, &self.metrics, disassembly_started_at);
    }

    pub(crate) fn begin_function(
        &self,
        address: u64,
        cfg: &mut Graph,
    ) -> Result<Option<Instant>, Error> {
        let function_started_at = Instant::now();
        self.metric_inc(&self.metrics.functions_processed, 1);
        cfg.functions.insert_processed(address);

        if self.known_function_addresses.contains(&address) {
            self.metric_inc(&self.metrics.functions_dedup_skipped, 1);
            self.metric_elapsed(&self.metrics.function_time_us, function_started_at);
            return Ok(None);
        }

        if !self.is_executable_address(address) {
            let error_message = format!(
                "Function -> 0x{:x}: it is not in executable memory",
                address
            );
            self.finish_function_invalid(address, cfg, function_started_at);
            Stderr::print_debug(&cfg.config, &error_message);
            return Err(Error::other(error_message));
        }

        Ok(Some(function_started_at))
    }

    pub(crate) fn finish_function_valid(
        &self,
        address: u64,
        cfg: &mut Graph,
        function_started_at: Instant,
    ) {
        cfg.functions.insert_valid(address);
        self.metric_inc(&self.metrics.functions_valid, 1);
        self.metric_elapsed(&self.metrics.function_time_us, function_started_at);
    }

    pub(crate) fn finish_function_invalid(
        &self,
        address: u64,
        cfg: &mut Graph,
        function_started_at: Instant,
    ) {
        cfg.functions.insert_invalid(address);
        self.metric_inc(&self.metrics.functions_invalid, 1);
        self.metric_elapsed(&self.metrics.function_time_us, function_started_at);
    }

    pub(crate) fn begin_instruction(
        &self,
        address: u64,
        cfg: &mut Graph,
    ) -> Result<Option<Instant>, Error> {
        let instruction_started_at = Instant::now();
        self.metric_inc(&self.metrics.instructions_processed, 1);
        cfg.instructions.insert_processed(address);

        if cfg.get_instruction(address).is_some() {
            self.metric_elapsed(&self.metrics.instruction_time_us, instruction_started_at);
            return Ok(None);
        }

        if !self.is_executable_address(address) {
            cfg.instructions.insert_invalid(address);
            self.metric_inc(&self.metrics.instructions_invalid, 1);
            self.metric_elapsed(&self.metrics.instruction_time_us, instruction_started_at);
            let error = format!(
                "Instruction -> 0x{:x}: it is not in executable memory",
                address
            );
            Stderr::print_debug(&cfg.config, error.clone());
            return Err(Error::other(error));
        }

        Ok(Some(instruction_started_at))
    }

    pub(crate) fn finish_instruction_invalid(
        &self,
        address: u64,
        cfg: &mut Graph,
        instruction_started_at: Instant,
    ) {
        cfg.instructions.insert_invalid(address);
        self.metric_inc(&self.metrics.instructions_invalid, 1);
        self.metric_elapsed(&self.metrics.instruction_time_us, instruction_started_at);
    }

    pub(crate) fn finish_instruction_valid(
        &self,
        address: u64,
        cfg: &mut Graph,
        instruction_started_at: Instant,
    ) {
        cfg.instructions.insert_valid(address);
        self.metric_inc(&self.metrics.instructions_valid, 1);
        self.metric_elapsed(&self.metrics.instruction_time_us, instruction_started_at);
    }

    pub(crate) fn begin_block(
        &self,
        address: u64,
        cfg: &mut Graph,
    ) -> Result<Option<Instant>, Error> {
        let block_started_at = Instant::now();
        self.metric_inc(&self.metrics.blocks_processed, 1);
        cfg.blocks.insert_processed(address);

        if self.known_block_addresses.contains(&address) {
            self.metric_inc(&self.metrics.blocks_dedup_skipped, 1);
            self.metric_elapsed(&self.metrics.block_time_us, block_started_at);
            return Ok(None);
        }

        if !self.is_executable_address(address) {
            cfg.functions.insert_invalid(address);
            self.metric_inc(&self.metrics.blocks_invalid, 1);
            self.metric_elapsed(&self.metrics.block_time_us, block_started_at);
            let error_message = format!("Block -> 0x{:x}: it is not in executable memory", address);
            Stderr::print_debug(&cfg.config, error_message.clone());
            return Err(Error::other(error_message));
        }

        Ok(Some(block_started_at))
    }

    pub(crate) fn finish_block_valid(
        &self,
        address: u64,
        cfg: &mut Graph,
        block_started_at: Instant,
    ) {
        cfg.blocks.insert_valid(address);
        self.metric_inc(&self.metrics.blocks_valid, 1);
        self.metric_elapsed(&self.metrics.block_time_us, block_started_at);
    }

    pub(crate) fn finish_block_invalid(
        &self,
        address: u64,
        cfg: &mut Graph,
        block_started_at: Instant,
    ) {
        cfg.blocks.insert_invalid(address);
        self.metric_inc(&self.metrics.blocks_invalid, 1);
        self.metric_elapsed(&self.metrics.block_time_us, block_started_at);
    }

    pub(crate) fn has_known_instruction_address(&self, address: u64) -> bool {
        self.known_instruction_addresses.contains(&address)
    }

    pub(crate) fn record_shared_tail_split(&self) {
        self.metric_inc(&self.metrics.shared_tail_splits, 1);
    }

    pub fn get_instruction_chromosome_mask(&self, instruction: &Insn) -> Result<Vec<u8>, Error> {
        let operands = self.get_instruction_operands(instruction)?;
        let decoded_operands = operands
            .iter()
            .filter_map(|operand| self.decode_history_operand(operand))
            .collect::<Vec<_>>();

        instruction_chromosome_mask(
            instruction.bytes(),
            Self::is_wildcard_instruction(instruction),
            &decoded_operands,
            Self::is_pair_memory_instruction(instruction),
        )
    }

    pub fn is_return_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_return_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_trap_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_trap_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_jump_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_jump_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_call_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_call_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_unconditional_jump_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_unconditional_jump_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_conditional_jump_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_conditional_jump_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub(crate) fn get_decoded_instruction(&self, address: u64) -> Option<Arm64DecodedInstruction> {
        if let Some(instruction) = self
            .decoded_instruction_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&address).cloned())
        {
            self.metric_inc(&self.metrics.decode_cache_hits, 1);
            return Some(instruction);
        }
        self.metric_inc(&self.metrics.decode_cache_misses, 1);

        let Ok(insns) = self.disassemble_instructions(address, 1) else {
            return None;
        };
        let Some(insn) = insns.iter().next() else {
            return None;
        };
        let Ok(operands) = self.get_instruction_operands(insn) else {
            return None;
        };

        let decoded = Arm64DecodedInstruction {
            address: insn.address(),
            mnemonic: insn.mnemonic().unwrap_or("").to_lowercase(),
            operands: operands
                .iter()
                .filter_map(|operand| self.decode_history_operand(operand))
                .collect(),
        };

        if let Ok(mut cache) = self.decoded_instruction_cache.lock() {
            cache.insert(address, decoded.clone());
        }

        Some(decoded)
    }

    pub fn is_load_address_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_load_address_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_wildcard_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_wildcard_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_nop_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_nop_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_pair_memory_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_pair_memory_mnemonic(instruction.mnemonic().unwrap_or(""))
    }

    pub fn is_privilege_instruction(instruction: &Insn) -> bool {
        arm64_classify::is_privilege_mnemonic(instruction.mnemonic().unwrap_or(""))
    }
}
