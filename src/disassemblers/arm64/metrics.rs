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

use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use crate::{Config, io::Stderr};

#[derive(Default)]
pub struct DisassemblyMetrics {
    pub sweep_time_us: AtomicU64,
    pub sweep_ranges: AtomicU64,
    pub sweep_pc_steps: AtomicU64,
    pub sweep_decode_failures: AtomicU64,
    pub sweep_valid_run_hits: AtomicU64,
    pub sweep_direct_calls: AtomicU64,
    pub sweep_candidates_accepted: AtomicU64,
    pub sweep_candidates_duplicate: AtomicU64,
    pub sweep_candidates_nonexec: AtomicU64,
    pub sweep_candidates_validation_rejected: AtomicU64,
    pub functions_processed: AtomicU64,
    pub functions_valid: AtomicU64,
    pub functions_invalid: AtomicU64,
    pub functions_dedup_skipped: AtomicU64,
    pub blocks_processed: AtomicU64,
    pub blocks_valid: AtomicU64,
    pub blocks_invalid: AtomicU64,
    pub blocks_dedup_skipped: AtomicU64,
    pub instructions_processed: AtomicU64,
    pub instructions_valid: AtomicU64,
    pub instructions_invalid: AtomicU64,
    pub shared_tail_splits: AtomicU64,
    pub decode_cache_hits: AtomicU64,
    pub decode_cache_misses: AtomicU64,
    pub indirect_target_calls: AtomicU64,
    pub indirect_targets_found: AtomicU64,
    pub function_time_us: AtomicU64,
    pub block_time_us: AtomicU64,
    pub instruction_time_us: AtomicU64,
    pub indirect_target_time_us: AtomicU64,
    pub semantics_time_us: AtomicU64,
    pub merge_time_us: AtomicU64,
}

pub fn group_function_addresses(addresses: &BTreeSet<u64>, group_size: usize) -> Vec<Vec<u64>> {
    let mut groups = Vec::new();
    let mut current = Vec::with_capacity(group_size);
    for address in addresses {
        current.push(*address);
        if current.len() == group_size {
            groups.push(current);
            current = Vec::with_capacity(group_size);
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

pub fn record_merge_elapsed_for_metrics(
    metrics: &Arc<DisassemblyMetrics>,
    merge_started_at: Instant,
    debug: bool,
) {
    if debug {
        metrics.merge_time_us.fetch_add(
            merge_started_at.elapsed().as_micros() as u64,
            Ordering::Relaxed,
        );
    }
}

pub fn log_disassembly_metrics(
    config: &Config,
    metrics: &Arc<DisassemblyMetrics>,
    disassembly_started_at: Instant,
) {
    if !config.debug {
        return;
    }

    let functions_processed = metrics.functions_processed.load(Ordering::Relaxed);
    let functions_valid = metrics.functions_valid.load(Ordering::Relaxed);
    let functions_invalid = metrics.functions_invalid.load(Ordering::Relaxed);
    let functions_dedup_skipped = metrics.functions_dedup_skipped.load(Ordering::Relaxed);
    let blocks_processed = metrics.blocks_processed.load(Ordering::Relaxed);
    let blocks_valid = metrics.blocks_valid.load(Ordering::Relaxed);
    let blocks_invalid = metrics.blocks_invalid.load(Ordering::Relaxed);
    let blocks_dedup_skipped = metrics.blocks_dedup_skipped.load(Ordering::Relaxed);
    let instructions_processed = metrics.instructions_processed.load(Ordering::Relaxed);
    let instructions_valid = metrics.instructions_valid.load(Ordering::Relaxed);
    let instructions_invalid = metrics.instructions_invalid.load(Ordering::Relaxed);
    let shared_tail_splits = metrics.shared_tail_splits.load(Ordering::Relaxed);
    let decode_cache_hits = metrics.decode_cache_hits.load(Ordering::Relaxed);
    let decode_cache_misses = metrics.decode_cache_misses.load(Ordering::Relaxed);
    let indirect_target_calls = metrics.indirect_target_calls.load(Ordering::Relaxed);
    let indirect_targets_found = metrics.indirect_targets_found.load(Ordering::Relaxed);
    let sweep_ranges = metrics.sweep_ranges.load(Ordering::Relaxed);
    let sweep_pc_steps = metrics.sweep_pc_steps.load(Ordering::Relaxed);
    let sweep_decode_failures = metrics.sweep_decode_failures.load(Ordering::Relaxed);
    let sweep_valid_run_hits = metrics.sweep_valid_run_hits.load(Ordering::Relaxed);
    let sweep_direct_calls = metrics.sweep_direct_calls.load(Ordering::Relaxed);
    let sweep_candidates_accepted = metrics.sweep_candidates_accepted.load(Ordering::Relaxed);
    let sweep_candidates_duplicate = metrics.sweep_candidates_duplicate.load(Ordering::Relaxed);
    let sweep_candidates_nonexec = metrics.sweep_candidates_nonexec.load(Ordering::Relaxed);
    let sweep_candidates_validation_rejected = metrics
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
        config,
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
            metrics.sweep_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
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
            metrics.function_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
            metrics.block_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
            metrics.instruction_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
            metrics.indirect_target_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
            metrics.semantics_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
            metrics.merge_time_us.load(Ordering::Relaxed) as f64 / 1000.0,
        ),
    );
}
