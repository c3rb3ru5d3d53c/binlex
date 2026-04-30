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

#[derive(Clone, Debug)]
pub struct Arm64DecodedInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: Vec<Arm64DecodedOperand>,
}

#[derive(Clone, Debug)]
pub struct Arm64DecodedMemoryOperand {
    pub base: Option<String>,
    pub index: Option<String>,
    pub displacement: i64,
    pub shift_amount: Option<u32>,
    pub extender: Option<String>,
    pub operand_size_bits: Option<usize>,
}

#[derive(Clone, Debug)]
pub enum Arm64DecodedOperand {
    Register(String),
    Immediate(i64),
    Memory(Arm64DecodedMemoryOperand),
    Invalid,
}

impl Arm64DecodedInstruction {
    pub fn mnemonic_is(&self, mnemonic: &str) -> bool {
        self.mnemonic == mnemonic
    }
}

pub fn canonical_register_family(name: &str) -> String {
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
    name.to_string()
}
