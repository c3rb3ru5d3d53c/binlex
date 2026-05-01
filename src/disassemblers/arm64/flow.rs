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
    is_call: bool,
    is_conditional_jump: bool,
) -> usize {
    if is_unconditional_jump {
        return 1;
    }
    if is_return {
        return 0;
    }
    if is_call {
        return 1;
    }
    if is_conditional_jump {
        return 2;
    }
    0
}

pub fn conditional_target_operand_index(mnemonic: &str) -> usize {
    match mnemonic {
        "cbz" | "cbnz" => 1,
        "tbz" | "tbnz" => 2,
        _ => 0,
    }
}

pub fn unconditional_target_operand_index(is_unconditional_jump: bool) -> Option<usize> {
    if is_unconditional_jump { Some(0) } else { None }
}

pub fn load_address_operand_index(is_load_address: bool) -> Option<usize> {
    if is_load_address { Some(1) } else { None }
}

pub fn indirect_target_operand_index(has_indirect_target: bool) -> Option<usize> {
    if has_indirect_target { Some(0) } else { None }
}

pub fn should_collect_indirect_targets(has_indirect_target: bool) -> bool {
    has_indirect_target
}
