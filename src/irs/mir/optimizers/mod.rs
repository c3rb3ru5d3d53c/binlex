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

pub mod abi;
pub mod blocks;
pub mod branches;
pub mod call_clobbers;
pub mod calls;
pub mod constants;
pub mod copy_propagation;
pub mod cse;
pub mod dead_effects;
pub mod flags;
pub mod intrinsics;
pub mod liveness;
pub mod memory_aliases;
pub mod memory_state;
pub mod register_state;
pub mod returns;
pub mod simplify;
pub mod ssa;
pub mod ssa_liveness;
pub mod stack;
pub mod stack_pointers;
pub mod stack_slots;
pub mod subexpressions;
pub mod targets;
pub mod undefs;

pub use abi::optimize_abi;
pub use blocks::optimize_blocks;
pub use branches::optimize_branches;
pub use call_clobbers::optimize_call_clobbers;
pub use calls::optimize_calls;
pub use constants::optimize_constants;
pub use copy_propagation::optimize_copy_propagation;
pub use cse::optimize_cse;
pub use dead_effects::optimize_dead_effects;
pub use flags::optimize_flags;
pub use intrinsics::optimize_intrinsics;
pub use liveness::optimize_liveness;
pub use memory_aliases::optimize_memory_aliases;
pub use memory_state::optimize_memory_state;
pub use register_state::optimize_register_state;
pub use returns::optimize_returns;
pub use simplify::optimize;
pub(crate) use simplify::optimize_with_timing;
pub use ssa::optimize_ssa;
pub use ssa_liveness::optimize_ssa_liveness;
pub use stack::optimize_stack;
pub use stack_pointers::optimize_stack_pointers;
pub use stack_slots::optimize_stack_slots;
pub use subexpressions::optimize_subexpressions;
pub use targets::optimize_targets;
pub use undefs::optimize_undefs;
