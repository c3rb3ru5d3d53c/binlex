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

pub fn instruction_edges(
    is_unconditional_jump: bool,
    is_return: bool,
    is_conditional_jump: bool,
) -> usize {
    if is_unconditional_jump {
        return 1;
    }
    if is_return {
        return 0;
    }
    if is_conditional_jump {
        return 2;
    }
    0
}

pub fn has_indirect_controlflow_target(
    is_call: bool,
    is_jump: bool,
    operand_is_register_or_memory: bool,
) -> bool {
    (is_call || is_jump) && operand_is_register_or_memory
}

pub fn should_expand_jump_table(is_unconditional_jump: bool) -> bool {
    is_unconditional_jump
}

pub fn has_pc_relative_controlflow_immediate(
    is_conditional_jump: bool,
    is_unconditional_jump: bool,
    is_call: bool,
) -> bool {
    is_conditional_jump || is_unconditional_jump || is_call
}

pub fn controlflow_target_operand_index(is_jump: bool, is_call: bool) -> Option<usize> {
    if is_jump || is_call {
        Some(0)
    } else {
        None
    }
}

pub fn load_address_target_from_memory(
    instruction_address: u64,
    instruction_size: usize,
    base: Option<&str>,
    index: Option<&str>,
    displacement: i64,
) -> Option<u64> {
    if index.is_some() {
        return None;
    }
    if base == Some("rip") {
        return Some((instruction_address as i64 + displacement + instruction_size as i64) as u64);
    }
    if base.is_none() {
        return Some(displacement as u64);
    }
    None
}
