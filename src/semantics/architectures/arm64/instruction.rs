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
use crate::semantics::architectures::arm64::operand::Arm64OperandView;

#[derive(Clone, Debug)]
pub struct InstructionDetailArm64 {
    pub machine: Architecture,
    pub address: u64,
    pub mnemonic: String,
    pub operand_text: Option<String>,
    pub bytes: Vec<u8>,
    pub operand_count: usize,
    pub operand_views: Vec<Arm64OperandView>,
    pub condition_code: Option<u64>,
}

impl InstructionDetailArm64 {
    pub fn new(
        machine: Architecture,
        address: u64,
        mnemonic: impl Into<String>,
        operand_text: Option<String>,
        bytes: Vec<u8>,
        operand_views: Vec<Arm64OperandView>,
        condition_code: Option<u64>,
    ) -> Self {
        Self {
            machine,
            address,
            mnemonic: mnemonic.into(),
            operand_count: operand_views.len(),
            operand_text,
            bytes,
            operand_views,
            condition_code,
        }
    }

    pub fn operand(&self, index: usize) -> Option<&Arm64OperandView> {
        self.operand_views.get(index)
    }

    pub fn operands(&self) -> &[Arm64OperandView] {
        &self.operand_views
    }

    pub fn mnemonic_lower(&self) -> String {
        self.mnemonic.to_ascii_lowercase()
    }
}
