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

use super::block::MirBlock;
use super::optimizers::{
    optimize_abi, optimize_blocks, optimize_branches, optimize_call_clobbers, optimize_calls,
    optimize_constants, optimize_copy_propagation, optimize_cse, optimize_dead_effects,
    optimize_flags, optimize_intrinsics, optimize_liveness, optimize_memory_aliases,
    optimize_memory_state, optimize_register_state, optimize_returns, optimize_simplify,
    optimize_ssa, optimize_ssa_liveness, optimize_stack, optimize_stack_pointers,
    optimize_stack_slots, optimize_subexpressions, optimize_targets, optimize_undefs,
};
use super::print::format_mir;
use crate::ir::lir::{LirAbi, LirModule};
use crate::ir::mir::lower::{MirLowerError, lower_lir_to_mir};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Mir {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<LirAbi>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<MirBlock>,
}

impl Mir {
    pub fn from_lir(name: Option<String>, lir: &LirModule) -> Result<Self, MirLowerError> {
        lower_lir_to_mir(name, lir)
    }

    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            abi: None,
            blocks: Vec::new(),
        }
    }

    pub fn blocks(&self) -> &[MirBlock] {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut Vec<MirBlock> {
        &mut self.blocks
    }

    pub fn append_block(&mut self, block: MirBlock) {
        self.blocks.push(block);
    }

    pub fn optimize_register_state(&mut self) {
        optimize_register_state(self);
    }

    pub fn optimize_returns(&mut self) {
        optimize_returns(self);
    }

    pub fn optimize_blocks(&mut self) {
        optimize_blocks(self);
    }

    pub fn optimize_abi(&mut self) {
        optimize_abi(self);
    }

    pub fn optimize_subexpressions(&mut self) {
        optimize_subexpressions(self);
    }

    pub fn optimize_flags(&mut self) {
        optimize_flags(self);
    }

    pub fn optimize_liveness(&mut self) {
        optimize_liveness(self);
    }

    pub fn optimize_undefs(&mut self) {
        optimize_undefs(self);
    }

    pub fn optimize_intrinsics(&mut self) {
        optimize_intrinsics(self);
    }

    pub fn optimize_cse(&mut self) {
        optimize_cse(self);
    }

    pub fn optimize_stack(&mut self) {
        optimize_stack(self);
    }

    pub fn optimize_stack_pointers(&mut self) {
        optimize_stack_pointers(self);
    }

    pub fn optimize_stack_slots(&mut self) {
        optimize_stack_slots(self);
    }

    pub fn optimize_calls(&mut self) {
        optimize_calls(self);
    }

    pub fn optimize_call_clobbers(&mut self) {
        optimize_call_clobbers(self);
    }

    pub fn optimize_memory_aliases(&mut self) {
        optimize_memory_aliases(self);
    }

    pub fn optimize_branches(&mut self) {
        optimize_branches(self);
    }

    pub fn optimize_memory_state(&mut self) {
        optimize_memory_state(self);
    }

    pub fn optimize_constants(&mut self) {
        optimize_constants(self);
    }

    pub fn optimize_dead_effects(&mut self) {
        optimize_dead_effects(self);
    }

    pub fn optimize_copy_propagation(&mut self) {
        optimize_copy_propagation(self);
    }

    pub fn optimize_targets(&mut self) {
        optimize_targets(self);
    }

    pub fn optimize_ssa(&mut self) {
        optimize_ssa(self);
    }

    pub fn optimize_ssa_liveness(&mut self) {
        optimize_ssa_liveness(self);
    }

    pub fn optimize_simplify(&mut self) {
        optimize_simplify(self);
    }

    pub fn text(&self) -> String {
        format_mir(self)
    }
}
