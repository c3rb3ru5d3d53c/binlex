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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arm64OperandKind {
    Register,
    Immediate,
    Memory,
    Float,
    System,
    Invalid,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Arm64MemoryOperandView {
    pub base_register_name: Option<String>,
    pub index_register_name: Option<String>,
    pub displacement: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Arm64ShiftKind {
    Lsl,
    Msl,
    Lsr,
    Asr,
    Ror,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Arm64OperandView {
    pub kind: Arm64OperandKind,
    pub size_bits: u16,
    pub register_name: Option<String>,
    pub immediate: Option<i64>,
    pub float: Option<f64>,
    pub memory: Option<Arm64MemoryOperandView>,
    pub vector_index: Option<u32>,
    pub vas: Option<u32>,
    pub shift: Option<(Arm64ShiftKind, u32)>,
    pub extender: Option<u32>,
}

impl Arm64OperandView {
    pub fn is_register(&self) -> bool {
        self.kind == Arm64OperandKind::Register
    }

    pub fn is_immediate(&self) -> bool {
        self.kind == Arm64OperandKind::Immediate
    }

    pub fn is_memory(&self) -> bool {
        self.kind == Arm64OperandKind::Memory
    }

    pub fn register_name(&self) -> Option<&str> {
        self.register_name.as_deref()
    }

    pub fn immediate_value(&self) -> Option<i64> {
        self.immediate
    }

    pub fn memory_operand(&self) -> Option<&Arm64MemoryOperandView> {
        self.memory.as_ref()
    }

    pub fn shift_amount(&self) -> Option<u32> {
        self.shift.map(|(_, amount)| amount)
    }
}
