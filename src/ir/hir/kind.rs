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

pub type HirAddressSpace = crate::ir::mir::MirAddressSpace;
pub type HirType = crate::ir::mir::MirType;
pub type HirTypeKind = crate::ir::mir::MirTypeKind;
pub type HirCompareOperation = crate::ir::mir::MirCompareOperation;
pub type HirFloatCompareOperation = crate::ir::mir::MirFloatCompareOperation;
pub type HirCastOperation = crate::ir::mir::MirCastOperation;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HirUnaryOperation {
    LogicalNot,
    BitNot,
    Neg,
    Popcount,
    CountLeadingZeros,
    CountTrailingZeros,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HirBinaryOperation {
    Add,
    Sub,
    Mul,
    FAdd,
    FSub,
    FMul,
    FDiv,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
    UDiv,
    SDiv,
    URem,
    SRem,
    RotateLeft,
    RotateRight,
}
