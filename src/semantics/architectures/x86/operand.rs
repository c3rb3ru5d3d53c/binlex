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
pub enum X86OperandKind {
    Register,
    Immediate,
    Memory,
    Invalid,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86MemoryOperandView {
    pub base_register_name: Option<&'static str>,
    pub index_register_name: Option<&'static str>,
    pub scale: i32,
    pub displacement: i64,
    pub segment_register_name: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X86OperandView {
    pub kind: X86OperandKind,
    pub size_bits: u16,
    pub register_name: Option<&'static str>,
    pub immediate: Option<i64>,
    pub memory: Option<X86MemoryOperandView>,
}

impl X86OperandView {
    pub fn is_register(&self) -> bool {
        self.kind == X86OperandKind::Register
    }

    pub fn is_immediate(&self) -> bool {
        self.kind == X86OperandKind::Immediate
    }

    pub fn is_memory(&self) -> bool {
        self.kind == X86OperandKind::Memory
    }

    pub fn register_name(&self) -> Option<&'static str> {
        self.register_name
    }

    pub fn immediate_value(&self) -> Option<i64> {
        self.immediate
    }

    pub fn memory_operand(&self) -> Option<&X86MemoryOperandView> {
        self.memory.as_ref()
    }
}
