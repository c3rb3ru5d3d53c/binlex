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
use crate::controlflow::{
    FloatOperand, ImmediateOperand, Instruction, MemoryOperand, Operand, OperandKind,
    RegisterOperand, SpecialOperand,
};
use crate::genetics::Chromosome;
use crate::io::Stderr;
use crate::semantics;
use crate::semantics::{InstructionSemantics, SemanticEffect, SemanticStatus};
use capstone::Insn;
use capstone::Instructions;
use capstone::RegId;
use capstone::arch::ArchOperand;
use capstone::arch::arm64::{Arm64Extender, Arm64Insn, Arm64OperandType, Arm64Shift};
use capstone::prelude::*;
use rayon::ThreadPoolBuilder;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone)]
struct DecodedInstruction {
    address: u64,
    id: u32,
    operands: Vec<ArchOperand>,
}

#[derive(Default)]
struct DisassemblyMetrics {
    sweep_time_us: AtomicU64,
    sweep_ranges: AtomicU64,
    sweep_pc_steps: AtomicU64,
    sweep_decode_failures: AtomicU64,
    sweep_valid_run_hits: AtomicU64,
    sweep_direct_calls: AtomicU64,
    sweep_candidates_accepted: AtomicU64,
    sweep_candidates_duplicate: AtomicU64,
    sweep_candidates_nonexec: AtomicU64,
    sweep_candidates_validation_rejected: AtomicU64,
    functions_processed: AtomicU64,
    functions_valid: AtomicU64,
    functions_invalid: AtomicU64,
    functions_dedup_skipped: AtomicU64,
    blocks_processed: AtomicU64,
    blocks_valid: AtomicU64,
    blocks_invalid: AtomicU64,
    blocks_dedup_skipped: AtomicU64,
    instructions_processed: AtomicU64,
    instructions_valid: AtomicU64,
    instructions_invalid: AtomicU64,
    shared_tail_splits: AtomicU64,
    decode_cache_hits: AtomicU64,
    decode_cache_misses: AtomicU64,
    indirect_target_calls: AtomicU64,
    indirect_targets_found: AtomicU64,
    function_time_us: AtomicU64,
    block_time_us: AtomicU64,
    instruction_time_us: AtomicU64,
    indirect_target_time_us: AtomicU64,
    semantics_time_us: AtomicU64,
    merge_time_us: AtomicU64,
}

pub struct Disassembler<'disassembler> {
    cs: Capstone,
    image: &'disassembler [u8],
    machine: Architecture,
    executable_address_ranges: BTreeMap<u64, u64>,
    config: Config,
    decoded_instruction_cache: Mutex<HashMap<u64, DecodedInstruction>>,
    metrics: Arc<DisassemblyMetrics>,
    known_instruction_addresses: Arc<BTreeSet<u64>>,
    known_block_addresses: Arc<BTreeSet<u64>>,
    known_function_addresses: Arc<BTreeSet<u64>>,
}

impl<'disassembler> Disassembler<'disassembler> {
    const SWEEP_CALLER_VALID_RUN: usize = 4;
    const SWEEP_CALLER_POST_RUN: usize = 2;
    const SWEEP_TARGET_VALID_RUN: usize = 2;
    const SWEEP_MIN_CALLERS_PER_TARGET: u64 = 2;
    const FUNCTION_GROUP_SIZE: usize = 4;

    fn log_semantics_debug(&self, semantics: &InstructionSemantics, instruction: &Insn) {
        let has_intrinsic_effect = semantics
            .effects
            .iter()
            .any(|effect| matches!(effect, SemanticEffect::Intrinsic { .. }));
        let intrinsic_effects = semantics
            .effects
            .iter()
            .filter_map(|effect| match effect {
                SemanticEffect::Intrinsic { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if semantics.status == SemanticStatus::Complete
            && semantics.diagnostics.is_empty()
            && !has_intrinsic_effect
        {
            return;
        }

        let bytes = instruction
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");

        let summary = if semantics.diagnostics.is_empty() {
            format!(
                "no diagnostics; mnemonic={}; op_str={}; bytes={}; effects={}; intrinsic_effects={}; terminator={:?}",
                instruction.mnemonic().unwrap_or("unknown"),
                instruction.op_str().unwrap_or(""),
                bytes,
                semantics.effects.len(),
                if intrinsic_effects.is_empty() {
                    "none".to_string()
                } else {
                    intrinsic_effects.join(",")
                },
                semantics.terminator.kind()
            )
        } else {
            format!(
                "mnemonic={}; op_str={}; bytes={}; intrinsic_effects={}; {}",
                instruction.mnemonic().unwrap_or("unknown"),
                instruction.op_str().unwrap_or(""),
                bytes,
                if intrinsic_effects.is_empty() {
                    "none".to_string()
                } else {
                    intrinsic_effects.join(",")
                },
                semantics
                    .diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            )
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
        Self::new_with_metrics(
            machine,
            image,
            executable_address_ranges,
            config,
            Arc::new(DisassemblyMetrics::default()),
            Arc::new(BTreeSet::new()),
            Arc::new(BTreeSet::new()),
            Arc::new(BTreeSet::new()),
        )
    }

    fn new_with_metrics(
        machine: Architecture,
        image: &'disassembler [u8],
        executable_address_ranges: BTreeMap<u64, u64>,
        config: Config,
        metrics: Arc<DisassemblyMetrics>,
        known_instruction_addresses: Arc<BTreeSet<u64>>,
        known_block_addresses: Arc<BTreeSet<u64>>,
        known_function_addresses: Arc<BTreeSet<u64>>,
    ) -> Result<Self, Error> {
        let cs = Self::cs_new(machine, true)?;
        Ok(Self {
            cs,
            image,
            machine,
            executable_address_ranges,
            config,
            decoded_instruction_cache: Mutex::new(HashMap::new()),
            metrics,
            known_instruction_addresses,
            known_block_addresses,
            known_function_addresses,
        })
    }

    fn metric_inc(&self, counter: &AtomicU64, value: u64) {
        if self.config.debug {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }

    fn metric_elapsed(&self, counter: &AtomicU64, started_at: Instant) {
        if self.config.debug {
            counter.fetch_add(started_at.elapsed().as_micros() as u64, Ordering::Relaxed);
        }
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

    fn register_name(&self, reg: RegId) -> Option<String> {
        if reg.0 == 0 {
            return None;
        }
        self.cs.reg_name(reg)
    }

    fn special_operand_fields() -> BTreeMap<String, Value> {
        BTreeMap::new()
    }

    fn parse_system_register_operands(&self, instruction: &Insn) -> Vec<Operand> {
        let mnemonic = instruction.mnemonic().unwrap_or("").to_ascii_lowercase();
        let parts: Vec<_> = instruction
            .op_str()
            .unwrap_or("")
            .split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .collect();

        match mnemonic.as_str() {
            "mrs" if parts.len() >= 2 => vec![
                Operand {
                    kind: OperandKind::Register(RegisterOperand {
                        name: parts[0].to_ascii_lowercase(),
                    }),
                },
                Operand {
                    kind: OperandKind::Special(SpecialOperand {
                        kind: "reg_mrs".to_string(),
                        fields: BTreeMap::from([(
                            "sysreg".to_string(),
                            Value::from(parts[1].to_string()),
                        )]),
                    }),
                },
            ],
            "msr" if parts.len() >= 2 => vec![
                Operand {
                    kind: OperandKind::Special(SpecialOperand {
                        kind: "reg_msr".to_string(),
                        fields: BTreeMap::from([(
                            "sysreg".to_string(),
                            Value::from(parts[0].to_string()),
                        )]),
                    }),
                },
                Operand {
                    kind: OperandKind::Register(RegisterOperand {
                        name: parts[1].to_ascii_lowercase(),
                    }),
                },
            ],
            _ => Vec::new(),
        }
    }

    fn normalize_operand(&self, operand: &ArchOperand) -> Option<Operand> {
        let ArchOperand::Arm64Operand(op) = operand else {
            return None;
        };
        let kind = match &op.op_type {
            Arm64OperandType::Reg(reg) => {
                let name = self.register_name(*reg)?;
                OperandKind::Register(RegisterOperand { name })
            }
            Arm64OperandType::Imm(value) | Arm64OperandType::Cimm(value) => {
                OperandKind::Immediate(ImmediateOperand {
                    value: *value as i128,
                })
            }
            Arm64OperandType::Mem(mem) => OperandKind::Memory(MemoryOperand {
                base: self.register_name(mem.base()),
                index: self.register_name(mem.index()),
                scale: None,
                displacement: mem.disp() as i64,
                space: None,
                segment: None,
            }),
            Arm64OperandType::Fp(value) => OperandKind::Float(FloatOperand { value: *value }),
            Arm64OperandType::RegMrs(sysreg) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("sysreg".to_string(), Value::from(format!("{:?}", sysreg)));
                OperandKind::Special(SpecialOperand {
                    kind: "reg_mrs".to_string(),
                    fields,
                })
            }
            Arm64OperandType::RegMsr(sysreg) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("sysreg".to_string(), Value::from(format!("{:?}", sysreg)));
                OperandKind::Special(SpecialOperand {
                    kind: "reg_msr".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Pstate(pstate) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("pstate".to_string(), Value::from(format!("{:?}", pstate)));
                OperandKind::Special(SpecialOperand {
                    kind: "pstate".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Sys(sys) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("sys".to_string(), Value::from(format!("{:?}", sys)));
                OperandKind::Special(SpecialOperand {
                    kind: "sys".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Prefetch(prefetch) => {
                let mut fields = Self::special_operand_fields();
                fields.insert(
                    "prefetch".to_string(),
                    Value::from(format!("{:?}", prefetch)),
                );
                OperandKind::Special(SpecialOperand {
                    kind: "prefetch".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Barrier(barrier) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("barrier".to_string(), Value::from(format!("{:?}", barrier)));
                OperandKind::Special(SpecialOperand {
                    kind: "barrier".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Invalid => {
                let fields = Self::special_operand_fields();
                OperandKind::Special(SpecialOperand {
                    kind: "invalid".to_string(),
                    fields,
                })
            }
        };
        Some(Operand { kind })
    }

    fn normalize_instruction_operands(&self, operands: &[ArchOperand]) -> Vec<Operand> {
        operands
            .iter()
            .filter_map(|operand| self.normalize_operand(operand))
            .collect()
    }

    fn disassembly_text(&self, instruction: &Insn) -> String {
        match instruction.op_str() {
            Some(op_str) if !op_str.is_empty() => {
                format!("{} {}", instruction.mnemonic().unwrap_or(""), op_str)
            }
            _ => instruction.mnemonic().unwrap_or("").to_string(),
        }
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.executable_address_ranges
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    pub fn disassemble_sweep(&self) -> BTreeSet<u64> {
        let sweep_started_at = Instant::now();
        let mut result = BTreeSet::new();
        let mut candidate_counts = BTreeMap::<u64, u64>::new();

        for (range_start, range_end) in &self.executable_address_ranges {
            self.metric_inc(&self.metrics.sweep_ranges, 1);
            let mut pc = *range_start;
            let mut valid_run_len = 0usize;

            while pc.checked_add(4).is_some_and(|next| next <= *range_end) {
                self.metric_inc(&self.metrics.sweep_pc_steps, 1);
                let (is_counted_instruction, direct_call_target) =
                    match self.disassemble_instructions(pc, 1) {
                        Ok(instructions) => match instructions.iter().next() {
                            Some(instruction) => (
                                self.is_sweep_counted_instruction(instruction),
                                if Self::is_direct_call_instruction(instruction) {
                                    self.get_call_immutable(instruction)
                                } else {
                                    None
                                },
                            ),
                            None => {
                                valid_run_len = 0;
                                pc += 4;
                                continue;
                            }
                        },
                        Err(_) => {
                            self.metric_inc(&self.metrics.sweep_decode_failures, 1);
                            valid_run_len = 0;
                            pc += 4;
                            continue;
                        }
                    };

                if is_counted_instruction {
                    valid_run_len += 1;
                } else {
                    valid_run_len = 0;
                }

                if valid_run_len >= Self::SWEEP_CALLER_VALID_RUN {
                    self.metric_inc(&self.metrics.sweep_valid_run_hits, 1);
                    if let Some(target) = direct_call_target {
                        self.metric_inc(&self.metrics.sweep_direct_calls, 1);
                        if !self.has_sweep_post_run(pc, *range_end) {
                            self.metric_inc(&self.metrics.sweep_candidates_validation_rejected, 1);
                        } else if !self.is_executable_address(target) {
                            self.metric_inc(&self.metrics.sweep_candidates_nonexec, 1);
                        } else {
                            let count = candidate_counts.entry(target).or_insert(0);
                            if *count > 0 {
                                self.metric_inc(&self.metrics.sweep_candidates_duplicate, 1);
                            }
                            *count += 1;
                        }
                    }
                }

                pc += 4;
            }
        }

        for (target, count) in candidate_counts {
            if count < Self::SWEEP_MIN_CALLERS_PER_TARGET {
                self.metric_inc(&self.metrics.sweep_candidates_validation_rejected, 1);
                continue;
            }

            if self.validate_sweep_target(target) {
                self.metric_inc(&self.metrics.sweep_candidates_accepted, 1);
                result.insert(target);
            } else {
                self.metric_inc(&self.metrics.sweep_candidates_validation_rejected, 1);
            }
        }

        self.metric_elapsed(&self.metrics.sweep_time_us, sweep_started_at);
        result
    }

    pub fn disassemble<'a>(
        &'a self,
        addresses: BTreeSet<u64>,
        cfg: &'a mut Graph,
    ) -> Result<(), Error> {
        let disassembly_started_at = Instant::now();
        let pool = ThreadPoolBuilder::new()
            .num_threads(cfg.config.resolved_threads())
            .build()
            .map_err(|error| Error::new(ErrorKind::Other, format!("{}", error)))?;

        let mut seed_addresses = addresses;
        seed_addresses.extend(self.disassemble_sweep());
        cfg.functions.enqueue_extend(seed_addresses);

        let external_image = self.image;
        let external_machine = self.machine;
        let external_executable_address_ranges = self.executable_address_ranges.clone();
        let external_config = self.config.clone();
        let graph_config = cfg.config.clone();
        let shared_metrics = self.metrics.clone();
        let batch_width = cfg.config.resolved_threads().max(1);

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
                    let function_groups = Self::group_function_addresses(&function_addresses);
                    let graphs: Vec<Graph> = function_groups
                        .par_iter()
                        .map_init(
                            || {
                                Disassembler::new_with_metrics(
                                    external_machine,
                                    external_image,
                                    external_executable_address_ranges.clone(),
                                    external_config.clone(),
                                    shared_metrics.clone(),
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
                        if graph_config.debug {
                            shared_metrics.merge_time_us.fetch_add(
                                merge_started_at.elapsed().as_micros() as u64,
                                Ordering::Relaxed,
                            );
                        }
                    }
                }
            }
        });

        if cfg.config.debug {
            let functions_processed = self.metrics.functions_processed.load(Ordering::Relaxed);
            let functions_valid = self.metrics.functions_valid.load(Ordering::Relaxed);
            let functions_invalid = self.metrics.functions_invalid.load(Ordering::Relaxed);
            let functions_dedup_skipped =
                self.metrics.functions_dedup_skipped.load(Ordering::Relaxed);
            let blocks_processed = self.metrics.blocks_processed.load(Ordering::Relaxed);
            let blocks_valid = self.metrics.blocks_valid.load(Ordering::Relaxed);
            let blocks_invalid = self.metrics.blocks_invalid.load(Ordering::Relaxed);
            let blocks_dedup_skipped = self.metrics.blocks_dedup_skipped.load(Ordering::Relaxed);
            let instructions_processed =
                self.metrics.instructions_processed.load(Ordering::Relaxed);
            let instructions_valid = self.metrics.instructions_valid.load(Ordering::Relaxed);
            let instructions_invalid = self.metrics.instructions_invalid.load(Ordering::Relaxed);
            let shared_tail_splits = self.metrics.shared_tail_splits.load(Ordering::Relaxed);
            let decode_cache_hits = self.metrics.decode_cache_hits.load(Ordering::Relaxed);
            let decode_cache_misses = self.metrics.decode_cache_misses.load(Ordering::Relaxed);
            let indirect_target_calls = self.metrics.indirect_target_calls.load(Ordering::Relaxed);
            let indirect_targets_found =
                self.metrics.indirect_targets_found.load(Ordering::Relaxed);
            let sweep_ranges = self.metrics.sweep_ranges.load(Ordering::Relaxed);
            let sweep_pc_steps = self.metrics.sweep_pc_steps.load(Ordering::Relaxed);
            let sweep_decode_failures = self.metrics.sweep_decode_failures.load(Ordering::Relaxed);
            let sweep_valid_run_hits = self.metrics.sweep_valid_run_hits.load(Ordering::Relaxed);
            let sweep_direct_calls = self.metrics.sweep_direct_calls.load(Ordering::Relaxed);
            let sweep_candidates_accepted = self
                .metrics
                .sweep_candidates_accepted
                .load(Ordering::Relaxed);
            let sweep_candidates_duplicate = self
                .metrics
                .sweep_candidates_duplicate
                .load(Ordering::Relaxed);
            let sweep_candidates_nonexec = self
                .metrics
                .sweep_candidates_nonexec
                .load(Ordering::Relaxed);
            let sweep_candidates_validation_rejected = self
                .metrics
                .sweep_candidates_validation_rejected
                .load(Ordering::Relaxed);
            let avg_blocks_per_function = if functions_valid == 0 {
                0.0
            } else {
                blocks_valid as f64 / functions_valid as f64
            };
            let avg_instructions_per_block = if blocks_valid == 0 {
                0.0
            } else {
                instructions_valid as f64 / blocks_valid as f64
            };
            Stderr::print_debug(
                &cfg.config,
                format!(
                    concat!(
                        "arm64 sweep: time_ms={:.3}, ranges={}, steps={}, decode_failures={}, ",
                        "valid_run_hits={}, direct_calls={}, accepted={}, duplicate={}, ",
                        "nonexec={}, validation_rejected={}\n",
                        "arm64 metrics: total_ms={:.3}, functions[p={},v={},i={},dedup={}], ",
                        "blocks[p={},v={},i={},dedup={},avg_per_fn={:.2}], ",
                        "instructions[p={},v={},i={},shared_tail_splits={},avg_per_block={:.2}], ",
                        "decode_cache[hits={},misses={}], indirect[calls={},targets={}], ",
                        "time_ms[fn={:.3},block={:.3},insn={:.3},indirect={:.3},semantics={:.3},merge={:.3}]"
                    ),
                    self.metrics.sweep_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
                    sweep_ranges,
                    sweep_pc_steps,
                    sweep_decode_failures,
                    sweep_valid_run_hits,
                    sweep_direct_calls,
                    sweep_candidates_accepted,
                    sweep_candidates_duplicate,
                    sweep_candidates_nonexec,
                    sweep_candidates_validation_rejected,
                    disassembly_started_at.elapsed().as_secs_f64() * 1000.0,
                    functions_processed,
                    functions_valid,
                    functions_invalid,
                    functions_dedup_skipped,
                    blocks_processed,
                    blocks_valid,
                    blocks_invalid,
                    blocks_dedup_skipped,
                    avg_blocks_per_function,
                    instructions_processed,
                    instructions_valid,
                    instructions_invalid,
                    shared_tail_splits,
                    avg_instructions_per_block,
                    decode_cache_hits,
                    decode_cache_misses,
                    indirect_target_calls,
                    indirect_targets_found,
                    self.metrics.function_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
                    self.metrics.block_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
                    self.metrics.instruction_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
                    self.metrics.indirect_target_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
                    self.metrics.semantics_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
                    self.metrics.merge_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
                ),
            );
        }

        Ok(())
    }

    pub fn disassemble_function<'a>(
        &'a self,
        address: u64,
        cfg: &'a mut Graph,
    ) -> Result<u64, Error> {
        let function_started_at = Instant::now();
        self.metric_inc(&self.metrics.functions_processed, 1);
        cfg.functions.insert_processed(address);

        if self.known_function_addresses.contains(&address) {
            self.metric_inc(&self.metrics.functions_dedup_skipped, 1);
            self.metric_elapsed(&self.metrics.function_time_us, function_started_at);
            return Ok(address);
        }

        if !self.is_executable_address(address) {
            cfg.functions.insert_invalid(address);
            self.metric_inc(&self.metrics.functions_invalid, 1);
            self.metric_elapsed(&self.metrics.function_time_us, function_started_at);
            let error_message = format!(
                "Function -> 0x{:x}: it is not in executable memory",
                address
            );
            Stderr::print_debug(&cfg.config, &error_message);
            return Err(Error::other(error_message));
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
        self.metric_inc(&self.metrics.functions_valid, 1);
        self.metric_elapsed(&self.metrics.function_time_us, function_started_at);

        Ok(address)
    }

    pub fn disassemble_instruction<'a>(
        &'a self,
        address: u64,
        cfg: &'a mut Graph,
    ) -> Result<u64, Error> {
        let instruction_started_at = Instant::now();
        self.metric_inc(&self.metrics.instructions_processed, 1);
        cfg.instructions.insert_processed(address);

        if let Some(instruction) = cfg.get_instruction(address) {
            self.metric_elapsed(&self.metrics.instruction_time_us, instruction_started_at);
            return Ok(instruction.address);
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

        let instruction_container = self.disassemble_instructions(address, 1)?;
        let instruction = instruction_container.iter().next().ok_or_else(|| {
            cfg.instructions.insert_invalid(address);
            self.metric_inc(&self.metrics.instructions_invalid, 1);
            let error = format!("0x{:x}: failed to disassemble instruction", address);
            Error::other(error)
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

        blinstruction.is_jump = Self::is_jump_instruction(instruction);
        blinstruction.is_call = Self::is_call_instruction(instruction);
        blinstruction.is_return = Self::is_return_instruction(instruction);
        blinstruction.is_trap = Self::is_trap_instruction(instruction);

        if blinstruction.is_jump {
            blinstruction.is_conditional = Self::is_conditional_jump_instruction(instruction);
        }

        blinstruction.edges = self.get_instruction_edges(instruction);
        blinstruction.bytes = instruction.bytes().to_vec();
        blinstruction.chromosome_mask = instruction_mask;
        blinstruction.pattern = instruction_signature;
        blinstruction.mnemonic = instruction.mnemonic().unwrap_or("").to_string();
        blinstruction.disassembly = self.disassembly_text(instruction);
        blinstruction.has_indirect_target = self.has_indirect_controlflow_target(instruction);
        let mnemonic = instruction.mnemonic().unwrap_or("").to_ascii_lowercase();
        let operands = if matches!(mnemonic.as_str(), "mrs" | "msr") {
            Vec::new()
        } else {
            self.get_instruction_operands(instruction)
                .unwrap_or_default()
        };
        blinstruction.operands = if matches!(mnemonic.as_str(), "mrs" | "msr") {
            self.parse_system_register_operands(instruction)
        } else {
            self.normalize_instruction_operands(&operands)
        };

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
        let indirect_targets = if blinstruction.has_indirect_target {
            self.get_indirect_controlflow_targets(instruction, cfg)
        } else {
            BTreeSet::new()
        };
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
            if self.is_function_prologue(addr) {
                cfg.functions.enqueue(addr);
                blinstruction.functions.insert(addr);
            }
        }

        if blinstruction.is_jump || blinstruction.is_return || blinstruction.is_trap {
            blinstruction.edges = blinstruction.blocks().len();
        }

        if cfg.config.semantics.enabled {
            let semantics_started_at = Instant::now();
            let condition_code = self
                .get_instruction_condition_code(instruction)
                .ok()
                .flatten();
            let semantics = semantics::capstone::arm64::build(
                self.machine,
                instruction,
                &operands,
                condition_code,
            );
            self.log_semantics_debug(&semantics, instruction);
            blinstruction.semantics = Some(semantics);
            self.metric_elapsed(&self.metrics.semantics_time_us, semantics_started_at);
        }

        Stderr::print_debug(
            &cfg.config,
            format!(
                "0x{:x}: mnemonic: {:?}, next: {:?}, to: {:?}, is_conditional: {:?}, is_jump: {:?}",
                blinstruction.address,
                instruction.mnemonic().unwrap_or(""),
                blinstruction.next(),
                blinstruction.to(),
                blinstruction.is_conditional,
                blinstruction.is_jump,
            ),
        );

        cfg.insert_instruction(blinstruction);
        cfg.instructions.insert_valid(address);
        self.metric_inc(&self.metrics.instructions_valid, 1);
        self.metric_elapsed(&self.metrics.instruction_time_us, instruction_started_at);

        Ok(address)
    }

    pub fn disassemble_block<'a>(&'a self, address: u64, cfg: &'a mut Graph) -> Result<u64, Error> {
        let block_started_at = Instant::now();
        self.metric_inc(&self.metrics.blocks_processed, 1);
        cfg.blocks.insert_processed(address);

        if self.known_block_addresses.contains(&address) {
            self.metric_inc(&self.metrics.blocks_dedup_skipped, 1);
            self.metric_elapsed(&self.metrics.block_time_us, block_started_at);
            return Ok(address);
        }

        if !self.is_executable_address(address) {
            cfg.functions.insert_invalid(address);
            self.metric_inc(&self.metrics.blocks_invalid, 1);
            self.metric_elapsed(&self.metrics.block_time_us, block_started_at);
            let error_message = format!("Block -> 0x{:x}: it is not in executable memory", address);
            Stderr::print_debug(&cfg.config, error_message.clone());
            return Err(Error::other(error_message));
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
                    self.metric_inc(&self.metrics.blocks_invalid, 1);
                    self.metric_elapsed(&self.metrics.block_time_us, block_started_at);
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

            if self.known_instruction_addresses.contains(&pc) {
                split_successor = Some(pc);
                self.metric_inc(&self.metrics.shared_tail_splits, 1);
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
        cfg.blocks.insert_valid(address);
        self.metric_inc(&self.metrics.blocks_valid, 1);
        self.metric_elapsed(&self.metrics.block_time_us, block_started_at);

        Ok(terminator)
    }

    pub fn is_function_prologue(&self, address: u64) -> bool {
        let Ok(instructions) = self.disassemble_instructions(address, 2) else {
            return false;
        };
        if instructions.len() < 2 {
            return false;
        }

        let first = &instructions[0];
        let second = &instructions[1];

        if first.id().0 != Arm64Insn::ARM64_INS_STP as u32
            || second.id().0 != Arm64Insn::ARM64_INS_MOV as u32
        {
            return false;
        }

        let Ok(first_operands) = self.get_instruction_operands(first) else {
            return false;
        };
        let Ok(second_operands) = self.get_instruction_operands(second) else {
            return false;
        };

        matches!(
            first_operands.as_slice(),
            [
                ArchOperand::Arm64Operand(dst0),
                ArchOperand::Arm64Operand(dst1),
                ArchOperand::Arm64Operand(mem)
            ]
            if matches!(dst0.op_type, Arm64OperandType::Reg(reg) if self.register_family(reg) == "x29")
                && matches!(dst1.op_type, Arm64OperandType::Reg(reg) if self.register_family(reg) == "x30")
                && matches!(mem.op_type, Arm64OperandType::Mem(_))
        ) && matches!(
            second_operands.as_slice(),
            [
                ArchOperand::Arm64Operand(dst),
                ArchOperand::Arm64Operand(src)
            ]
            if matches!(dst.op_type, Arm64OperandType::Reg(reg) if self.register_family(reg) == "x29")
                && matches!(src.op_type, Arm64OperandType::Reg(reg) if self.register_family(reg) == "sp")
        )
    }

    pub fn get_instruction_chromosome_mask(&self, instruction: &Insn) -> Result<Vec<u8>, Error> {
        if Self::is_wildcard_instruction(instruction) {
            return Ok(vec![0xFF; instruction.bytes().len()]);
        }

        let operands = self.get_instruction_operands(instruction)?;
        let has_memory_operand = operands.iter().any(|operand| {
            matches!(
                operand,
                ArchOperand::Arm64Operand(op) if matches!(op.op_type, Arm64OperandType::Mem(_))
            )
        });

        if !has_memory_operand {
            return Ok(vec![0; instruction.bytes().len()]);
        }

        if instruction.bytes().len() != 4 {
            return Ok(vec![0; instruction.bytes().len()]);
        }

        // AArch64 addressing is encoded in fixed bit ranges within the 32-bit
        // instruction word. Mask only the address-forming bits so the opcode and
        // transferred register/class remain stable in the chromosome.
        let bit_range = if Self::is_pair_memory_instruction(instruction) {
            (5usize, 21usize)
        } else {
            (5usize, 20usize)
        };

        Ok(Self::mask_bits(
            instruction.bytes().len(),
            bit_range.0,
            bit_range.1,
        ))
    }

    fn mask_bits(byte_len: usize, start_bit: usize, end_bit: usize) -> Vec<u8> {
        let mut mask = vec![0u8; byte_len];
        for bit in start_bit..=end_bit {
            let byte_index = bit / 8;
            let bit_index = bit % 8;
            if byte_index < mask.len() {
                mask[byte_index] |= 1 << bit_index;
            }
        }
        mask
    }

    pub fn get_call_immutable(&self, instruction: &Insn) -> Option<u64> {
        if Self::is_call_instruction(instruction) {
            let operand = self.get_instruction_operand(instruction, 0).ok()?;
            return Self::get_operand_immutable(&operand);
        }
        None
    }

    pub fn get_operand_immutable(op: &ArchOperand) -> Option<u64> {
        if let ArchOperand::Arm64Operand(op) = op {
            match op.op_type {
                Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => {
                    return Some(imm as u64);
                }
                _ => {}
            }
        }
        None
    }

    pub fn get_instruction_operands(&self, instruction: &Insn) -> Result<Vec<ArchOperand>, Error> {
        let detail = self
            .cs
            .insn_detail(instruction)
            .map_err(|_| Error::other("failed to get instruction detail"))?;
        let arch = detail.arch_detail();
        Ok(arch.operands())
    }

    pub fn get_instruction_condition_code(&self, instruction: &Insn) -> Result<Option<u64>, Error> {
        let detail = self
            .cs
            .insn_detail(instruction)
            .map_err(|_| Error::other("failed to get instruction detail"))?;
        let arch = detail.arch_detail();
        Ok(arch.arm64().map(|detail| detail.cc() as u64))
    }

    pub fn get_instruction_operand(
        &self,
        instruction: &Insn,
        index: usize,
    ) -> Result<ArchOperand, Error> {
        let operands = self.get_instruction_operands(instruction)?;
        operands
            .get(index)
            .cloned()
            .ok_or_else(|| Error::other("failed to get instruction operand"))
    }

    pub fn get_instruction_edges(&self, instruction: &Insn) -> usize {
        if Self::is_unconditional_jump_instruction(instruction) {
            return 1;
        }
        if Self::is_return_instruction(instruction) {
            return 0;
        }
        if Self::is_call_instruction(instruction) {
            return 1;
        }
        if Self::is_conditional_jump_instruction(instruction) {
            return 2;
        }
        0
    }

    pub fn is_return_instruction(instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_RET as u32
                || id == Arm64Insn::ARM64_INS_RETAA as u32
                || id == Arm64Insn::ARM64_INS_RETAB as u32
        )
    }

    pub fn is_trap_instruction(instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_BRK as u32
                || id == Arm64Insn::ARM64_INS_HLT as u32
                || id == Arm64Insn::ARM64_INS_HVC as u32
                || id == Arm64Insn::ARM64_INS_SMC as u32
        )
    }

    pub fn is_jump_instruction(instruction: &Insn) -> bool {
        Self::is_conditional_jump_instruction(instruction)
            || Self::is_unconditional_jump_instruction(instruction)
    }

    pub fn is_call_instruction(instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_BL as u32
                || id == Arm64Insn::ARM64_INS_BLR as u32
                || id == Arm64Insn::ARM64_INS_BLRAA as u32
                || id == Arm64Insn::ARM64_INS_BLRAAZ as u32
                || id == Arm64Insn::ARM64_INS_BLRAB as u32
                || id == Arm64Insn::ARM64_INS_BLRABZ as u32
        )
    }

    pub fn is_unconditional_jump_instruction(instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_B as u32
                || id == Arm64Insn::ARM64_INS_BR as u32
                || id == Arm64Insn::ARM64_INS_BRAA as u32
                || id == Arm64Insn::ARM64_INS_BRAAZ as u32
                || id == Arm64Insn::ARM64_INS_BRAB as u32
                || id == Arm64Insn::ARM64_INS_BRABZ as u32
        ) && !instruction.mnemonic().unwrap_or("").starts_with("b.")
    }

    pub fn is_conditional_jump_instruction(instruction: &Insn) -> bool {
        let mnemonic = instruction.mnemonic().unwrap_or("");
        mnemonic.starts_with("b.")
            || matches!(
                instruction.id().0,
                id if id == Arm64Insn::ARM64_INS_CBZ as u32
                    || id == Arm64Insn::ARM64_INS_CBNZ as u32
                    || id == Arm64Insn::ARM64_INS_TBZ as u32
                    || id == Arm64Insn::ARM64_INS_TBNZ as u32
            )
    }

    pub fn get_conditional_jump_immutable(&self, instruction: &Insn) -> Option<u64> {
        if !Self::is_conditional_jump_instruction(instruction) {
            return None;
        }

        let index = match instruction.id().0 {
            id if id == Arm64Insn::ARM64_INS_CBZ as u32
                || id == Arm64Insn::ARM64_INS_CBNZ as u32 =>
            {
                1
            }
            id if id == Arm64Insn::ARM64_INS_TBZ as u32
                || id == Arm64Insn::ARM64_INS_TBNZ as u32 =>
            {
                2
            }
            _ => 0,
        };

        let operand = self.get_instruction_operand(instruction, index).ok()?;
        Self::get_operand_immutable(&operand)
    }

    pub fn get_unconditional_jump_immutable(&self, instruction: &Insn) -> Option<u64> {
        if !Self::is_unconditional_jump_instruction(instruction) {
            return None;
        }
        let operand = self.get_instruction_operand(instruction, 0).ok()?;
        Self::get_operand_immutable(&operand)
    }

    pub fn get_instruction_executable_addresses(&self, instruction: &Insn) -> Option<u64> {
        if !Self::is_load_address_instruction(instruction) {
            return None;
        }
        let operand = self.get_instruction_operand(instruction, 1).ok()?;
        let addr = Self::get_operand_immutable(&operand)?;
        self.is_executable_address(addr).then_some(addr)
    }

    pub fn has_indirect_controlflow_target(&self, instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_BR as u32
                || id == Arm64Insn::ARM64_INS_BLR as u32
                || id == Arm64Insn::ARM64_INS_BRAA as u32
                || id == Arm64Insn::ARM64_INS_BRAAZ as u32
                || id == Arm64Insn::ARM64_INS_BRAB as u32
                || id == Arm64Insn::ARM64_INS_BRABZ as u32
                || id == Arm64Insn::ARM64_INS_BLRAA as u32
                || id == Arm64Insn::ARM64_INS_BLRAAZ as u32
                || id == Arm64Insn::ARM64_INS_BLRAB as u32
                || id == Arm64Insn::ARM64_INS_BLRABZ as u32
                || id == Arm64Insn::ARM64_INS_RET as u32
                || id == Arm64Insn::ARM64_INS_RETAA as u32
                || id == Arm64Insn::ARM64_INS_RETAB as u32
        )
    }

    fn get_indirect_controlflow_target(&self, instruction: &Insn, cfg: &Graph) -> Option<u64> {
        if !self.has_indirect_controlflow_target(instruction) {
            return None;
        }
        let operand = self.get_instruction_operand(instruction, 0).ok()?;
        let ArchOperand::Arm64Operand(op) = operand else {
            return None;
        };
        let Arm64OperandType::Reg(reg) = op.op_type else {
            return None;
        };
        let history = self.get_recent_decoded_instructions(instruction.address(), cfg, 8);
        let target = self.resolve_register_value_from_history(reg, &history)?;
        self.is_executable_address(target).then_some(target)
    }

    fn get_indirect_controlflow_targets(&self, instruction: &Insn, cfg: &Graph) -> BTreeSet<u64> {
        let indirect_started_at = Instant::now();
        self.metric_inc(&self.metrics.indirect_target_calls, 1);
        let mut targets = BTreeSet::new();
        let history = self.get_recent_decoded_instructions(instruction.address(), cfg, 12);
        if let Ok(ArchOperand::Arm64Operand(op)) = self.get_instruction_operand(instruction, 0) {
            if let Arm64OperandType::Reg(reg) = op.op_type {
                targets.extend(self.resolve_register_jump_table_targets(reg, &history));
            }
        }
        if targets.is_empty() {
            if let Some(target) = self.get_indirect_controlflow_target(instruction, cfg) {
                targets.insert(target);
            }
        }
        self.metric_inc(&self.metrics.indirect_targets_found, targets.len() as u64);
        self.metric_elapsed(&self.metrics.indirect_target_time_us, indirect_started_at);
        targets
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
        let Some((base_reg, index_reg, entry_size)) = self.get_memory_source(load) else {
            return result;
        };
        let Some(case_count) = self.find_jump_table_case_count(index_reg, &history[..=load_index])
        else {
            return result;
        };
        let Some(table_base) =
            self.resolve_register_value_from_history(base_reg, &history[..=load_index])
        else {
            return result;
        };

        if load.id == Arm64Insn::ARM64_INS_LDR as u32 {
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

        if load.id != Arm64Insn::ARM64_INS_LDRSW as u32 {
            return result;
        }

        let Some(add_index) = history.iter().rposition(|insn| {
            insn.address > load.address && self.is_add_same_register(insn, jump_register)
        }) else {
            return result;
        };
        let Some(base_register) = self.get_add_rhs_register(&history[add_index], jump_register)
        else {
            return result;
        };
        let Some(code_base) =
            self.resolve_register_value_from_history(base_register, &history[..=add_index])
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
            let target = (code_base as i64 + offset as i64) as u64;
            if !self.is_executable_address(target) {
                break;
            }
            result.insert(target);
        }
        result
    }

    fn get_recent_decoded_instructions(
        &self,
        address: u64,
        cfg: &Graph,
        max_count: usize,
    ) -> Vec<DecodedInstruction> {
        let mut addresses = VecDeque::with_capacity(max_count);
        for entry in cfg.listing.range(..address) {
            if addresses.len() == max_count {
                addresses.pop_front();
            }
            addresses.push_back(*entry.key());
        }
        let mut decoded = Vec::new();
        for address in addresses {
            if let Some(instruction) = self.get_decoded_instruction(address) {
                decoded.push(instruction);
            }
        }
        decoded
    }

    fn get_decoded_instruction(&self, address: u64) -> Option<DecodedInstruction> {
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

        let decoded = DecodedInstruction {
            address: insn.address(),
            id: insn.id().0,
            operands,
        };

        if let Ok(mut cache) = self.decoded_instruction_cache.lock() {
            cache.insert(address, decoded.clone());
        }

        Some(decoded)
    }

    fn resolve_register_value_from_history(
        &self,
        register: RegId,
        history: &[DecodedInstruction],
    ) -> Option<u64> {
        let mut visited = BTreeSet::<String>::new();
        self.resolve_register_value_from_history_inner(register, history, &mut visited)
    }

    fn resolve_register_value_from_history_inner(
        &self,
        register: RegId,
        history: &[DecodedInstruction],
        visited: &mut BTreeSet<String>,
    ) -> Option<u64> {
        let family = self.register_family(register);
        if !visited.insert(family) {
            return None;
        }

        for instruction in history.iter().rev() {
            let Some(dst) = self.get_defined_register(instruction) else {
                continue;
            };
            if !self.registers_match(dst, register) {
                continue;
            }

            if instruction.id == Arm64Insn::ARM64_INS_ADR as u32
                || instruction.id == Arm64Insn::ARM64_INS_ADRP as u32
            {
                let operand = instruction.operands.get(1)?;
                if let Some(value) = Self::get_operand_immutable(operand) {
                    return Some(value);
                }
            }

            if instruction.id == Arm64Insn::ARM64_INS_MOV as u32 {
                let operand = instruction.operands.get(1)?;
                match operand {
                    ArchOperand::Arm64Operand(op) => match op.op_type {
                        Arm64OperandType::Imm(imm) => return Some(imm as u64),
                        Arm64OperandType::Reg(src) => {
                            return self
                                .resolve_register_value_from_history_inner(src, history, visited);
                        }
                        _ => continue,
                    },
                    _ => continue,
                }
            }

            if instruction.id == Arm64Insn::ARM64_INS_ADD as u32 {
                let src = match instruction.operands.get(1) {
                    Some(ArchOperand::Arm64Operand(op)) => match op.op_type {
                        Arm64OperandType::Reg(reg) => reg,
                        _ => continue,
                    },
                    _ => continue,
                };
                let imm = instruction
                    .operands
                    .get(2)
                    .and_then(Self::get_operand_immutable)?;
                let base = self.resolve_register_value_from_history_inner(src, history, visited)?;
                return base.checked_add(imm);
            }
        }
        None
    }

    fn is_register_jump_table_load(
        &self,
        instruction: &DecodedInstruction,
        register: RegId,
    ) -> bool {
        if instruction.operands.len() < 2 {
            return false;
        }
        if instruction.id != Arm64Insn::ARM64_INS_LDR as u32
            && instruction.id != Arm64Insn::ARM64_INS_LDRSW as u32
        {
            return false;
        }

        matches!(
            (&instruction.operands[0], &instruction.operands[1]),
            (ArchOperand::Arm64Operand(dst), ArchOperand::Arm64Operand(src))
                if matches!(dst.op_type, Arm64OperandType::Reg(reg) if self.registers_match(reg, register))
                    && matches!(src.op_type, Arm64OperandType::Mem(mem) if mem.index() != RegId(0))
        )
    }

    fn get_memory_source(&self, instruction: &DecodedInstruction) -> Option<(RegId, RegId, usize)> {
        if instruction.operands.len() < 2 {
            return None;
        }
        let (load_op, mem_op) = match (&instruction.operands[0], &instruction.operands[1]) {
            (ArchOperand::Arm64Operand(load), ArchOperand::Arm64Operand(mem)) => (load, mem),
            _ => return None,
        };

        let Arm64OperandType::Mem(mem) = mem_op.op_type else {
            return None;
        };
        if mem.base() == RegId(0) || mem.index() == RegId(0) {
            return None;
        }

        let entry_size = match instruction.id {
            id if id == Arm64Insn::ARM64_INS_LDRSW as u32 => 4,
            id if id == Arm64Insn::ARM64_INS_LDR as u32 => match load_op.op_type {
                Arm64OperandType::Reg(reg) => {
                    if self.register_family(reg).starts_with('w') {
                        4
                    } else {
                        8
                    }
                }
                _ => return None,
            },
            _ => return None,
        };

        let scale = match mem_op.shift {
            Arm64Shift::Lsl(value) => 1usize.checked_shl(value).unwrap_or(entry_size),
            _ => entry_size,
        };

        let final_entry_size = if matches!(
            mem_op.ext,
            Arm64Extender::ARM64_EXT_UXTW
                | Arm64Extender::ARM64_EXT_SXTW
                | Arm64Extender::ARM64_EXT_UXTX
                | Arm64Extender::ARM64_EXT_SXTX
        ) {
            scale
        } else {
            entry_size.max(scale)
        };

        Some((mem.base(), mem.index(), final_entry_size))
    }

    fn is_add_same_register(&self, instruction: &DecodedInstruction, register: RegId) -> bool {
        if instruction.id != Arm64Insn::ARM64_INS_ADD as u32 || instruction.operands.len() < 3 {
            return false;
        }
        matches!(
            &instruction.operands[0],
            ArchOperand::Arm64Operand(dst)
                if matches!(dst.op_type, Arm64OperandType::Reg(reg) if self.registers_match(reg, register))
        )
    }

    fn get_add_rhs_register(&self, instruction: &DecodedInstruction, lhs: RegId) -> Option<RegId> {
        if !self.is_add_same_register(instruction, lhs) {
            return None;
        }
        let src1 = match &instruction.operands[1] {
            ArchOperand::Arm64Operand(op) => match op.op_type {
                Arm64OperandType::Reg(reg) => reg,
                _ => return None,
            },
            _ => return None,
        };
        let src2 = match &instruction.operands[2] {
            ArchOperand::Arm64Operand(op) => match op.op_type {
                Arm64OperandType::Reg(reg) => reg,
                _ => return None,
            },
            _ => return None,
        };

        if self.registers_match(src1, lhs) && !self.registers_match(src2, lhs) {
            return Some(src2);
        }
        if self.registers_match(src2, lhs) && !self.registers_match(src1, lhs) {
            return Some(src1);
        }
        None
    }

    fn find_jump_table_case_count(
        &self,
        index_register: RegId,
        history: &[DecodedInstruction],
    ) -> Option<usize> {
        for instruction in history.iter().rev() {
            if instruction.id != Arm64Insn::ARM64_INS_CMP as u32 || instruction.operands.len() < 2 {
                continue;
            }
            let lhs_matches = matches!(
                &instruction.operands[0],
                ArchOperand::Arm64Operand(op)
                    if matches!(op.op_type, Arm64OperandType::Reg(reg) if self.registers_match(reg, index_register))
            );
            if !lhs_matches {
                continue;
            }
            if let ArchOperand::Arm64Operand(rhs) = &instruction.operands[1] {
                if let Arm64OperandType::Imm(imm) = rhs.op_type {
                    let count = (imm + 1).max(0) as usize;
                    if (1..=4096).contains(&count) {
                        return Some(count);
                    }
                }
            }
        }
        None
    }

    fn get_defined_register(&self, instruction: &DecodedInstruction) -> Option<RegId> {
        match instruction.operands.first() {
            Some(ArchOperand::Arm64Operand(op)) => match op.op_type {
                Arm64OperandType::Reg(reg) => Some(reg),
                _ => None,
            },
            _ => None,
        }
    }

    fn registers_match(&self, lhs: RegId, rhs: RegId) -> bool {
        self.register_family(lhs) == self.register_family(rhs)
    }

    fn register_family(&self, reg: RegId) -> String {
        let Some(name) = self.cs.reg_name(reg) else {
            return format!("reg_{}", reg.0);
        };
        if name == "fp" {
            return "x29".to_string();
        }
        if name == "lr" {
            return "x30".to_string();
        }
        if let Some(index) = name.strip_prefix('w') {
            return format!("x{}", index);
        }
        if name == "wsp" {
            return "sp".to_string();
        }
        name
    }

    pub fn is_load_address_instruction(instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_ADR as u32 || id == Arm64Insn::ARM64_INS_ADRP as u32
        )
    }

    pub fn is_wildcard_instruction(instruction: &Insn) -> bool {
        Self::is_nop_instruction(instruction) || Self::is_trap_instruction(instruction)
    }

    fn is_direct_call_instruction(instruction: &Insn) -> bool {
        instruction.id().0 == Arm64Insn::ARM64_INS_BL as u32
    }

    fn is_sweep_counted_instruction(&self, instruction: &Insn) -> bool {
        !Self::is_nop_instruction(instruction)
            && !Self::is_trap_instruction(instruction)
            && !Self::is_privilege_instruction(instruction)
    }

    fn validate_sweep_target(&self, address: u64) -> bool {
        if !self.is_executable_address(address) {
            return false;
        }

        let mut pc = address;
        let mut valid_count = 0usize;

        while valid_count < Self::SWEEP_TARGET_VALID_RUN {
            let instruction_size = match self.disassemble_instructions(pc, 1) {
                Ok(instructions) => match instructions.iter().next() {
                    Some(instruction) if self.is_sweep_counted_instruction(instruction) => {
                        instruction.bytes().len() as u64
                    }
                    None => return false,
                    Some(_) => return false,
                },
                Err(_) => return false,
            };

            valid_count += 1;
            pc += instruction_size;
        }

        true
    }

    fn has_sweep_post_run(&self, call_address: u64, range_end: u64) -> bool {
        let mut pc = call_address.saturating_add(4);
        let mut valid_count = 0usize;

        while valid_count < Self::SWEEP_CALLER_POST_RUN {
            if pc.checked_add(4).is_none_or(|next| next > range_end) {
                return false;
            }

            let instruction_size = match self.disassemble_instructions(pc, 1) {
                Ok(instructions) => match instructions.iter().next() {
                    Some(instruction) if self.is_sweep_counted_instruction(instruction) => {
                        instruction.bytes().len() as u64
                    }
                    None => return false,
                    Some(_) => return false,
                },
                Err(_) => return false,
            };

            valid_count += 1;
            pc += instruction_size;
        }

        true
    }

    pub fn is_nop_instruction(instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_NOP as u32 || id == Arm64Insn::ARM64_INS_HINT as u32
        )
    }

    pub fn is_pair_memory_instruction(instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_LDP as u32
                || id == Arm64Insn::ARM64_INS_LDPSW as u32
                || id == Arm64Insn::ARM64_INS_STP as u32
        )
    }

    pub fn is_privilege_instruction(instruction: &Insn) -> bool {
        matches!(
            instruction.id().0,
            id if id == Arm64Insn::ARM64_INS_HVC as u32
                || id == Arm64Insn::ARM64_INS_SMC as u32
                || id == Arm64Insn::ARM64_INS_SVC as u32
                || id == Arm64Insn::ARM64_INS_PRFM as u32
        )
    }

    pub fn disassemble_instructions(
        &self,
        address: u64,
        count: u64,
    ) -> Result<Instructions<'_>, Error> {
        if (address as usize) >= self.image.len() {
            return Err(Error::other("address out of bounds"));
        }
        let instructions = self
            .cs
            .disasm_count(&self.image[address as usize..], address, count as usize)
            .map_err(|_| Error::other("failed to disassemble instructions"))?;
        if instructions.is_empty() {
            return Err(Error::other("no instructions found"));
        }
        Ok(instructions)
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

    fn cs_new(machine: Architecture, detail: bool) -> Result<Capstone, Error> {
        match machine {
            Architecture::ARM64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(detail)
                .build()
                .map_err(|e| Error::other(format!("capstone error: {:?}", e))),
            _ => Err(Error::other("unsupported architecture")),
        }
    }
}
