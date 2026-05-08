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

use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct InstructionDetailCil {
    pub mnemonic: String,
    pub address: u64,
    operand_bytes: Vec<u8>,
    fallthrough: Option<u64>,
    targets: BTreeSet<u64>,
    is_call: bool,
    is_return: bool,
    is_jump: bool,
    is_conditional_jump: bool,
    is_switch: bool,
}

impl InstructionDetailCil {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mnemonic: String,
        address: u64,
        operand_bytes: Vec<u8>,
        fallthrough: Option<u64>,
        targets: BTreeSet<u64>,
        is_call: bool,
        is_return: bool,
        is_jump: bool,
        is_conditional_jump: bool,
        is_switch: bool,
    ) -> Self {
        Self {
            mnemonic,
            address,
            operand_bytes,
            fallthrough,
            targets,
            is_call,
            is_return,
            is_jump,
            is_conditional_jump,
            is_switch,
        }
    }

    pub fn operand_size(&self) -> usize {
        self.operand_bytes.len()
    }

    pub fn mnemonic_text(&self) -> &str {
        self.mnemonic.as_str()
    }

    pub fn operand_bytes(&self) -> &[u8] {
        &self.operand_bytes
    }

    pub fn fallthrough(&self) -> Option<u64> {
        self.fallthrough
    }

    pub fn branches(&self) -> &BTreeSet<u64> {
        &self.targets
    }

    pub fn is_call(&self) -> bool {
        self.is_call
    }

    pub fn is_return(&self) -> bool {
        self.is_return
    }

    pub fn is_jump(&self) -> bool {
        self.is_jump
    }

    pub fn is_conditional_jump(&self) -> bool {
        self.is_conditional_jump
    }

    pub fn is_switch(&self) -> bool {
        self.is_switch
    }
}
