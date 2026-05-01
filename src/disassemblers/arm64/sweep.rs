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
    collections::{BTreeMap, BTreeSet},
    io::Error,
    sync::Arc,
};

use crate::{
    Architecture, Config,
    controlflow::{Graph, Instruction},
    disassemblers::arm64::{classify as arm64_classify, metrics::DisassemblyMetrics},
};

const SWEEP_CALLER_VALID_RUN: usize = 4;
const SWEEP_CALLER_POST_RUN: usize = 2;
const SWEEP_TARGET_VALID_RUN: usize = 2;
const SWEEP_MIN_CALLERS_PER_TARGET: u64 = 2;

pub fn disassemble<F>(
    machine: Architecture,
    executable_address_ranges: &BTreeMap<u64, u64>,
    config: &Config,
    metrics: &Arc<DisassemblyMetrics>,
    mut prepare_instruction: F,
    is_executable_address: impl Fn(u64) -> bool,
) -> BTreeSet<u64>
where
    F: FnMut(u64, &Graph) -> Result<Instruction, Error>,
{
    let sweep_started_at = std::time::Instant::now();
    let graph = Graph::new(machine, config.clone());
    let mut result = BTreeSet::new();
    let mut candidate_counts = BTreeMap::<u64, u64>::new();

    for (range_start, range_end) in executable_address_ranges {
        metrics
            .sweep_ranges
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut pc = *range_start;
        let mut valid_run_len = 0usize;

        while pc.checked_add(4).is_some_and(|next| next <= *range_end) {
            metrics
                .sweep_pc_steps
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let prepared = match prepare_instruction(pc, &graph) {
                Ok(prepared) => prepared,
                Err(_) => {
                    metrics
                        .sweep_decode_failures
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    valid_run_len = 0;
                    pc += 4;
                    continue;
                }
            };
            let is_counted_instruction = !arm64_classify::is_nop_mnemonic(&prepared.mnemonic)
                && !arm64_classify::is_trap_mnemonic(&prepared.mnemonic)
                && !arm64_classify::is_privilege_mnemonic(&prepared.mnemonic);

            if is_counted_instruction {
                valid_run_len += 1;
            } else {
                valid_run_len = 0;
            }

            if valid_run_len >= SWEEP_CALLER_VALID_RUN {
                metrics
                    .sweep_valid_run_hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if arm64_classify::is_direct_call_mnemonic(&prepared.mnemonic) {
                    if let Some(target) = prepared.functions.iter().next().copied() {
                        metrics
                            .sweep_direct_calls
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if !has_sweep_post_run(pc, *range_end, &graph, &mut prepare_instruction) {
                            metrics
                                .sweep_candidates_validation_rejected
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        } else if !is_executable_address(target) {
                            metrics
                                .sweep_candidates_nonexec
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            let count = candidate_counts.entry(target).or_insert(0);
                            if *count > 0 {
                                metrics
                                    .sweep_candidates_duplicate
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            *count += 1;
                        }
                    }
                }
            }

            pc += prepared.bytes.len() as u64;
        }
    }

    for (target, count) in candidate_counts {
        if count < SWEEP_MIN_CALLERS_PER_TARGET {
            metrics
                .sweep_candidates_validation_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }
        if validate_sweep_target(
            target,
            &graph,
            &mut prepare_instruction,
            &is_executable_address,
        ) {
            metrics
                .sweep_candidates_accepted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            result.insert(target);
        } else {
            metrics
                .sweep_candidates_validation_rejected
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    metrics.sweep_time_us.fetch_add(
        sweep_started_at.elapsed().as_micros() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    result
}

fn validate_sweep_target<F>(
    address: u64,
    graph: &Graph,
    prepare_instruction: &mut F,
    is_executable_address: &impl Fn(u64) -> bool,
) -> bool
where
    F: FnMut(u64, &Graph) -> Result<Instruction, Error>,
{
    if !is_executable_address(address) {
        return false;
    }

    let mut pc = address;
    let mut valid_count = 0usize;
    while valid_count < SWEEP_TARGET_VALID_RUN {
        let size = match prepare_instruction(pc, graph) {
            Ok(prepared)
                if !arm64_classify::is_nop_mnemonic(&prepared.mnemonic)
                    && !arm64_classify::is_trap_mnemonic(&prepared.mnemonic)
                    && !arm64_classify::is_privilege_mnemonic(&prepared.mnemonic) =>
            {
                prepared.bytes.len() as u64
            }
            _ => return false,
        };
        valid_count += 1;
        pc += size;
    }
    true
}

fn has_sweep_post_run<F>(
    call_address: u64,
    range_end: u64,
    graph: &Graph,
    prepare_instruction: &mut F,
) -> bool
where
    F: FnMut(u64, &Graph) -> Result<Instruction, Error>,
{
    let mut pc = call_address.saturating_add(4);
    let mut valid_count = 0usize;
    while valid_count < SWEEP_CALLER_POST_RUN {
        if pc.checked_add(4).is_none_or(|next| next > range_end) {
            return false;
        }
        let size = match prepare_instruction(pc, graph) {
            Ok(prepared)
                if !arm64_classify::is_nop_mnemonic(&prepared.mnemonic)
                    && !arm64_classify::is_trap_mnemonic(&prepared.mnemonic)
                    && !arm64_classify::is_privilege_mnemonic(&prepared.mnemonic) =>
            {
                prepared.bytes.len() as u64
            }
            _ => return false,
        };
        valid_count += 1;
        pc += size;
    }
    true
}
