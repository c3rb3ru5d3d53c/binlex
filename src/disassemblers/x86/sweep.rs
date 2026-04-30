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

use std::{collections::{BTreeMap, BTreeSet}, io::Error};

use crate::{
    Architecture, Config,
    controlflow::{Graph, Instruction},
    disassemblers::x86::classify as x86_classify,
};

pub fn disassemble<F>(
    machine: Architecture,
    executable_address_ranges: &BTreeMap<u64, u64>,
    config: &Config,
    mut prepare_instruction: F,
    is_executable_address: impl Fn(u64) -> bool,
) -> BTreeSet<u64>
where
    F: FnMut(u64, &Graph) -> Result<Instruction, Error>,
{
    let valid_jump_threshold: usize = 2;
    let valid_instruction_threshold: usize = 4;
    let graph = Graph::new(machine, config.clone());

    let mut functions = BTreeSet::<u64>::new();
    for (start, end) in executable_address_ranges {
        let mut pc = *start;
        let mut valid_instructions = 0;
        let mut valid_jumps = 0;
        while pc < *end {
            let prepared = match prepare_instruction(pc, &graph) {
                Ok(prepared) => prepared,
                Err(_) => {
                    pc += 1;
                    valid_instructions = 0;
                    valid_jumps = 0;
                    continue;
                }
            };
            if x86_classify::is_privilege_mnemonic(&prepared.mnemonic)
                || x86_classify::is_trap_mnemonic(&prepared.mnemonic)
            {
                pc += prepared.bytes.len() as u64;
                continue;
            }
            let jump_target = if prepared.is_jump {
                prepared.to.iter().next().copied()
            } else {
                None
            };
            if let Some(imm) = jump_target {
                if is_executable_address(imm) {
                    valid_jumps += 1;
                } else {
                    valid_instructions = 0;
                    valid_jumps = 0;
                    pc += 1;
                    continue;
                }
            }
            if let Some(imm) = prepared.functions.iter().next().copied() {
                if valid_jumps >= valid_jump_threshold
                    && valid_instructions >= valid_instruction_threshold
                {
                    if is_executable_address(imm) {
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
            pc += prepared.bytes.len() as u64;
        }
    }
    functions
}
